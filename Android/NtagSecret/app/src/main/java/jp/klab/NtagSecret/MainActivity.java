/*
    NtagSecret

    - NXP 製 NFC タグ NTAG213, NTAG216 へ所定のテキストデータを圧縮して格納し
      全メモリページについて Read/Write 要求に対するパスワード保護を設定する
    - データが収まらない場合は後続の NTAG へ分割格納し連番で管理
    - NTAG の 4バイトのパスワード領域には 4バイトの ASCII キャラクタコードではなく
      パスワードとして指定された文字列の CRC32 値を格納する
    - NTAG への上記の Write 機能に加え Read機能, パスワード解除＆データ初期化機能をもつ

   2017.12

   Copyright 2017 KLab Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package jp.klab.NtagSecret;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareUltralight;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/*
本アプリでの NTAG ユーザメモリの使いかた

 ========= ユーザメモリ領域全体の構成 =========

 1. page 04h - 05h に固有の管理情報を格納する
 2. page 06h 以降に gzip データを格納する

 ========= 1. 管理情報について =========

 [page 04h]
    0    1    2    3
  +----+----+----+----+
  |'t' |'t' | -- | -- |
  +----+----+----+----+

  第 1, 2 バイト
    識別子 "tt"

  第 3, 4 バイト
    予備
    ※当初、データを分割格納したタグセットの識別用領域と
      することを想定したが費用対効果に乏しいと判断し中止

 [page 05h]
    0    1    2    3
  +----+----+----+----+
  | NN | -- | NN | NN |
  +----+----+----+----+

  第 1 バイト
   最上位ビット：後続タグの有無  0=後続なし 1=後続あり
   下位 4 ビット：タグ連番（0h - Fh）

  第 2 バイト
   予備

  第 3, 4 バイト
   ページ 06h 以降に格納ずみの gzip データサイズ
   short ビッグエンディアン

 ========= 2. gzip データについて =========

  - テキストデータの gzip 圧縮はオンメモリで行う

  - タグへ書き込む際には gzip データの半固定ヘッダ
    10バイト(*)を除去し、読み出しの際には当該ヘッダを
    補填した上で unpack する
    (*) http://www.onicos.com/staff/iz/formats/gzip.html

  - データを複数のタグへ分割格納する場合は上記の管理情報で
    連番管理を行うが、事後に各タグから単独で部分データを
    読み出すことも可能とするために、タグへ書き込むのは
    「元データ全体を圧縮した gzip データの一部分」ではなく
    「元データを適切な位置で分割して圧縮した gzip データ」とする
*/

public class MainActivity extends AppCompatActivity
        implements Handler.Callback, View.OnClickListener,
            RadioGroup.OnCheckedChangeListener, TextWatcher {

    private static final String TAG = "NTAG01";
    private static final String CHARSET = "Shift-JIS";
    private static final int NTAG_UNUSABLE_BYTES = 36; // 9 page
    private static final int NTAG213_TOTALPAGE = 0x2D; //  45
    private static final int NTAG215_TOTALPAGE = 0x87; // 135
    private static final int NTAG216_TOTALPAGE = 0xE7; // 231
    private static final int TAGCOUNT_MAX = 15;

    // gzip ヘッダ
    private static final int GZIP_HEADER_LENGTH = 10;
    private static final byte[] GZIP_HEADER = new byte[]{
            (byte) 0x1F, (byte) 0x8B, (byte) 0x08, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    // 本アプリ用タグヘッダ
    private static final int APP_HEADER_LENGTH = 8;
    private static byte[] APP_HEADER = new byte[]{
            't', 't', (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    private static final int MSG_YES = 10;
    private static final int MSG_NO = 11;
    private static final int MSG_ENDW = 13;
    private static final int MSG_NEEDAUTH = 14;
    private static final int MSG_PROGRESS = 15;
    private static final int MSG_SETNEXTTAG = 16;
    private static final int MSG_CANCEL = 17;
    private static final int MSG_ERASETEXT = 18;
    private static final int MSG_TAGINITDONE = 19;
    private static final int MSG_ISNOTTARGET = 20;
    private static final int MSG_DATACHANGED = 21;
    private static final int MSG_QUERYUSER = 22;
    private static final int MSG_ANOTHER_PWD = 23;
    private static final int MSG_TAGCOUNTOVER = 24;
    private static final int MSG_SHOWUI = 25;
    private static final int MSG_EMPTYTEXT = 27;
    private static final int MSG_SHOWDATA = 28;
    private static final int MSG_SUCCESS = 100;
    private static final int MSG_ERROR = 200;
    private static final int MSG_DO_INITDONE = 400;
    private static final int MSG_DO_READNEXT = 410;
    private static final int MSG_DO_WRITE = 420;
    private static final int MSG_DO_RELEASE = 430;

    private NfcAdapter mAdapter;
    private NfcA mNfca = null;
    private Tag mTag;
    private Handler mHandler;
    private TextView mDataLength, mClear, mTvTest;
    private EditText mPassword, mTextData;
    private AlertDialog mDlg;
    private ProgressDialog mProgressDlg;
    private RadioGroup mRadioGrp;
    private RadioButton mRadioRead, mRadioWrite, mRadioInit;
    private boolean mInitDone = false;
    private int mNtagTotalPage, mNtagConfPage0;
    private int mTagCount = 0, mNextOfs = 0;
    private String mStrData = "";
    private int mNext = -1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "onCreate");
        setContentView(R.layout.activity_main);
        mHandler = new Handler(this);
        mDataLength = (TextView) findViewById(R.id.dataLength);
        mClear = (TextView) findViewById(R.id.clear);
        mTvTest = (TextView) findViewById(R.id.tVTest);
        mClear.setOnClickListener(this);
        mTvTest.setOnClickListener(this);
        mPassword = (EditText) findViewById(R.id.password);
        mTextData = (EditText) findViewById(R.id.textData);
        mTextData.addTextChangedListener(this);
        mRadioGrp = (RadioGroup) findViewById(R.id.radiogroup);
        mRadioGrp.setOnCheckedChangeListener(this);
        mTextData.setVisibility(View.INVISIBLE);
        mRadioRead = (RadioButton) findViewById(R.id.rbRead);
        mRadioWrite = (RadioButton) findViewById(R.id.rbWrite);
        mRadioInit = (RadioButton) findViewById(R.id.rbInit);
        mRadioWrite.setEnabled(false);
        mRadioInit.setEnabled(false);

        mAdapter = NfcAdapter.getDefaultAdapter(this);
        if (mAdapter == null) {
            showDialogMessageOK(this, "NFC アダプタの取得に失敗しました", true);
            return;
        }
        if (!mAdapter.isEnabled()) {
            showDialogMessageOK(this, "NFC 機能を有効にして実行して下さい ", true);
            return;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.d(TAG, "onResume");
        // NFC_A 以外も検知対象とする
        mAdapter.enableReaderMode(this, new ReaderCBallback(),
                NfcAdapter.FLAG_READER_NFC_A |
                        NfcAdapter.FLAG_READER_NFC_B |
                        NfcAdapter.FLAG_READER_NFC_F, null);
    }

    @Override
    protected void onPause() {
        super.onPause();
        Log.d(TAG, "onPause");
        mAdapter.disableReaderMode(this);
    }

    @Override
    public void onStop() {
        super.onStop();
        Log.d(TAG, "onStop");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "onDestroy");
    }

    @Override
    public void onStart() {
        super.onStart();
        Log.d(TAG, "onStart");
    }

    @Override
    public void onClick(View v) {
        if (v == (View) mClear) {
            mTagCount = 0;
            mNextOfs = 0;
            mHandler.sendEmptyMessage(MSG_ERASETEXT);
        } else if (v == (View) mTvTest) {
            if (mPassword.length() == 0) {
                mPassword.setText("This_is_test_password");
            } else {
                mPassword.setText("");
            }
        }
    }

    @Override
    public void onCheckedChanged(RadioGroup group, int checkedId) {
        Log.d(TAG, "onCheckedChanged");
        mTagCount = 0;
        mNextOfs = 0;
        if (checkedId == R.id.rbRead || checkedId == R.id.rbInit) {
            mHandler.sendEmptyMessage(MSG_ERASETEXT);
        }
    }

    @Override
    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
    }

    @Override
    public void onTextChanged(CharSequence s, int start, int before, int count) {
    }

    @Override
    public void afterTextChanged(Editable s) {
        mHandler.sendEmptyMessage(MSG_DATACHANGED);
    }

    // タグを検知
    private class ReaderCBallback implements NfcAdapter.ReaderCallback {
        @Override
        public void onTagDiscovered(Tag tag) {
            mNtagTotalPage = getNtagPageCount(tag);
            // NTAG213, NTAG216 のみを対象とする
            switch (mNtagTotalPage) {
                case NTAG213_TOTALPAGE:
                    mNtagConfPage0 = mNtagTotalPage - 4;
                    break;
                case NTAG216_TOTALPAGE:
                    mNtagConfPage0 = mNtagTotalPage - 4;
                    break;
                case NTAG215_TOTALPAGE:
                default:
                    mNtagConfPage0 = -1;
                    mHandler.sendEmptyMessage(MSG_ISNOTTARGET);
                    return;
            }
            mTag = tag;
            mNfca = NfcA.get(mTag);
            if (!mInitDone) {
                readTag();
                mInitDone = true;
            } else {
                if (mRadioRead.isChecked()) {
                    readTag();
                } else if (mRadioWrite.isChecked()) {
                    writeTag();
                } else if (mRadioInit.isChecked()) {
                    releaseTag();
                }
            }
        }
    }

    private void doIt(final int what) {
        if (what == MSG_DO_INITDONE) {
            mInitDone = true;
            mHandler.sendEmptyMessage(MSG_SHOWUI);
        } else {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    if (what == MSG_DO_READNEXT) {
                        readTag1();
                    } else if (what == MSG_DO_WRITE) {
                        writeTag1();
                    } else if (what == MSG_DO_RELEASE) {
                        releaseTag1();
                    }
                }
            }).start();
        }
    }

    // タグからのデータ読み出し
    private void readTag() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                readTag1();
            }
        }).start();
    }

    private void readTag1() {
        Log.d(TAG, "readTag1 mTagCount=" + mTagCount);
        mHandler.sendEmptyMessage(MSG_PROGRESS);
        boolean isReadProtected = false;

        if (connectNfcA(mNfca) != 0) {
            mHandler.sendEmptyMessage(MSG_ERROR);
            return;
        }

        byte[] res = null;
        int sts = isPasswordProtectedTag(mNfca);
        if (sts == 1) {
            isReadProtected = true;
        }

        if (isReadProtected) {
            byte[] p = getPassword();
            if (p == null) {
                closeNfcA(mNfca);
                mHandler.sendEmptyMessage(MSG_NEEDAUTH);
                return;
            } else {
                sts = passwordAuth(mNfca, p);
                if (sts != 1) { // 認証 NG
                    closeNfcA(mNfca);
                    mHandler.sendEmptyMessage(MSG_NEEDAUTH);
                    return;
                }
            }
            // page 4,5.. を read
            try {
                res = mNfca.transceive(new byte[]{
                        (byte) 0x30, // READ
                        (byte) 0x04  // page address
                });
                Log.d(TAG, "res=" + bytesToHexString(res));
            } catch (IOException e) {
                Log.d(TAG, "READ err=" + e.toString());
                closeNfcA(mNfca);
                mHandler.sendEmptyMessage(MSG_ERROR);
                return;
            }
        }
        // ヘッダ先頭 = "tt" が本アプリ用タグの識別子
        if (res == null || !(res[0] == 't' && res[1] == 't')) {
            closeNfcA(mNfca);
            Message msg = new Message();
            if (mTagCount == 0) {
                msg.what = MSG_QUERYUSER;
                msg.obj = "本プログラム形式のデータが記録されていません。このタグを本プログラムで使用しますか？";
                msg.arg1 = MSG_DO_INITDONE;
            } else {
                msg.what = MSG_SHOWDATA;
                msg.obj = null; // 当該連番のタグへの接近を促す
                msg.arg1 = mTagCount;
            }
            mHandler.sendMessage(msg);
            return;
        }

        boolean hasNextTag = false;
        int tagcnt = 0;
        Log.d(TAG, "res[4]=" + res[4] + " (res[4] & 0x0F)=" + (byte) (res[4] & 0x0F));
        if ((res[4] & 0x80) != 0) {
            hasNextTag = true;
        }
        tagcnt = (int) (res[4] & 0x0F);
        Log.d(TAG, "hasNextTag=" + hasNextTag + " tagcnt=" + tagcnt);

        if (tagcnt != mTagCount) {
            if (mTagCount == 0) {
                mTagCount = tagcnt;
            } else {
                closeNfcA(mNfca);
                Message msg = new Message();
                msg.what = MSG_QUERYUSER;
                msg.obj = "これは記録セットの " + (mTagCount + 1) +
                        "枚めのタグではありません。かまわず読み込みますか？";
                msg.arg1 = MSG_DO_READNEXT;
                mHandler.sendMessage(msg);
                return;
            }
        }

        // 書き込まれている gzip データ長を得る
        byte[] wk = new byte[2];
        System.arraycopy(res, 6, wk, 0, 2);
        //Log.d(TAG, "res[6]=" + res[6] + " res[7]=" + res[7]);
        int gzipDataLength = ByteBuffer.wrap(wk).getShort();
        Log.d(TAG, "gzipDataLength=" + gzipDataLength);
        // READ すべき回数 （read は 4ページ = 16バイト単位）
        int readMax = gzipDataLength / 16 + ((gzipDataLength % 16 == 0) ? 0 : 1);
        Log.d(TAG, "readMax=" + readMax);

        int page = 0x06;
        byte[] gzipData = new byte[gzipDataLength];
        for (int i = 0; i < readMax; i++) {
            try {
                res = mNfca.transceive(new byte[]{
                        (byte) 0x30, // READ
                        (byte) (page + i * 4)
                });
                //Log.d(TAG, "res=" + bytesToHexString(res));
                if (i == readMax - 1) {
                    // 最後の READ 時には残データ長に留意
                    System.arraycopy(res, 0, gzipData, i * 16, gzipDataLength - i * 16);
                } else {
                    System.arraycopy(res, 0, gzipData, i * 16, 16);
                }
            } catch (IOException e) {
                Log.d(TAG, "READ err=" + e.toString());
                closeNfcA(mNfca);
                mHandler.sendEmptyMessage(MSG_ERROR);
                return;
            }
        }
        closeNfcA(mNfca);
        mInitDone = true;
        // unpack
        String s = gzipUnpackString(gzipData);

        // UI へテキストを表示
        mStrData = s;
        Message msg = new Message();
        msg.what = MSG_SHOWDATA;
        msg.obj = s;
        if (hasNextTag) {
            mTagCount++;
        } else {
            mTagCount = 0;
        }
        mHandler.sendMessage(msg);
    }

    // タグへのデータ書き込み
    private void writeTag() {
        byte[] pwd = getPassword();
        // パスワード未指定
        if (pwd == null) {
            mHandler.sendEmptyMessage(MSG_NEEDAUTH);
            return;
        }
        // データ未指定
        if (mTextData.getText().toString().length() <= 0) {
            mHandler.sendEmptyMessage(MSG_EMPTYTEXT);
            return;
        }
        Message msg = new Message();
        msg.what = MSG_QUERYUSER;
        msg.obj = "タグへ書き込みを行います。既存のデータは上書きされます。よろしいですか？";
        msg.arg1 = MSG_DO_WRITE;
        mHandler.sendMessage(msg);
    }

    private void writeTag1() {
        Log.d(TAG, "writeTag1");
        byte[] pwd = getPassword();
        mHandler.sendEmptyMessage(MSG_PROGRESS);
        mStrData = mTextData.getText().toString().substring(mNextOfs);

        int page = 0;
        byte[] pageData = new byte[4];
        byte[] packed = gzipPackString(mStrData);

        String s = gzipUnpackString(packed);
        //Log.d(TAG, "s=[" + s + "]");

        if (mStrData.length() > s.length() && mTagCount < TAGCOUNT_MAX) {
            mNextOfs += s.length();
        } else {
            mNextOfs = 0;
        }
        Log.d(TAG, "org len=" + mStrData.length() + " cur len=" + s.length() + " mNextOfs=" + mNextOfs);

        short gzipDataLength = (short) packed.length;

        if (connectNfcA(mNfca) != 0) {
            mHandler.sendEmptyMessage(MSG_ERROR);
            return;
        }

        int sts = isPasswordProtectedTag(mNfca);
        Log.d(TAG, "isPasswordProtectedTag sts=" + sts);
        if (sts == 1) {
            sts = passwordAuth(mNfca, getPassword());
            if (sts == 0) {
                closeNfcA(mNfca);
                mHandler.sendEmptyMessage(MSG_ANOTHER_PWD);
                return;
            }
        }

        // 以下、危険の少ない順に書き込み
        // 1. gzip データ本体
        // 2. 本アプリ用ヘッダ
        // 3. パスワード
        // 4. ACESSS への Read 保護設定 + AUTHLIM の自爆設定
        // 5. AUTH0 （保護開始ページ）

        // 1. gzip データ書き込み
        Log.d(TAG, "start to write gzip data");
        s = "";
        page = 0x06;
        for (int idx = 0; page < mNtagTotalPage - 5; idx += 4, page++) {
            if (idx >= packed.length) {
                break;
            } else if (idx + 3 < packed.length) {
                System.arraycopy(packed, idx, pageData, 0, 4);
            } else {
                int len = packed.length - idx;
                Arrays.fill(pageData, (byte) 0x00);
                System.arraycopy(packed, idx, pageData, 0, len);
            }

            try {
                byte[] res = mNfca.transceive(
                        new byte[]{
                                (byte) 0xA2, // WRITE
                                (byte) page, // page
                                pageData[0],
                                pageData[1],
                                pageData[2],
                                pageData[3],
                        }
                );
                //Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));
            } catch (IOException e) {
                Log.d(TAG, "NTAG  WRITE err:" + e.toString());
            }
            //Log.d(TAG, "page=" + page + " data=" + bytesToHexString(pageData));
        }
        Log.d(TAG, "done: current page=" + page);

        // 2. ヘッダ書き込み
        Log.d(TAG, "start to write App header");
        try {
            page = 0x04;
            byte[] res = mNfca.transceive(
                    new byte[]{
                            (byte) 0xA2, // WRITE
                            (byte) page,
                            APP_HEADER[0],
                            APP_HEADER[1],
                            APP_HEADER[2],
                            APP_HEADER[3]
                    }
            );
            Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

            page = 0x05;
            Log.d(TAG, "mTagCount=" + mTagCount);
            byte[] cnt = ByteBuffer.allocate(4).putInt(mTagCount).array();
            APP_HEADER[4] = (byte) (((mNextOfs > 0) ? 0x80 : 0x00) | (cnt[3] & 0x0F));
            mTagCount++;

            APP_HEADER[5] = 0x00; // 予備
            byte[] size = ByteBuffer.allocate(2).putShort(gzipDataLength).array();
            APP_HEADER[6] = size[0];
            APP_HEADER[7] = size[1];

            res = mNfca.transceive(
                    new byte[]{
                            (byte) 0xA2, // WRITE
                            (byte) page,
                            APP_HEADER[4],
                            APP_HEADER[5],
                            APP_HEADER[6],
                            APP_HEADER[7],
                    }
            );
            Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));
        } catch (IOException e) {
            Log.d(TAG, "NTAG  WRITE1 err: page=" + page + " :" + e.toString());
        }

        Log.d(TAG, "mNtagConfPage0=" + mNtagConfPage0);
        try {
            // 3. パスワードを書き込む
            Log.d(TAG, "start to write PWD");
            page = mNtagConfPage0 + 2; // config page 2
            byte[] res = mNfca.transceive(
                    new byte[]{
                            (byte) 0xA2, // WRITE
                            (byte) page,
                            pwd[0], pwd[1], pwd[2], pwd[3]
                    }
            );
            Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

            // 4. read からの保護設定有効化 および パスワード試行上限回数の AUTHLIM で自爆設定
            Log.d(TAG, "start to write PROT & AUTHLIM");
            page = mNtagConfPage0 + 1; // config page 1
            res = mNfca.transceive(
                    new byte[]{
                            (byte) 0xA2, // WRITE
                            (byte) page,
                            //(byte) 0x03, // write protect, AUTHLIM=3
                            (byte) 0x83, // read,write protect, AUTHLIM=3
                            (byte) 0x05,
                            (byte) 0x00,
                            (byte) 0x00
                    }
            );
            Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

            // 5. 保護開始ページを設定
            Log.d(TAG, "start to write AUTH0");
            page = mNtagConfPage0; // config page 0
            res = mNfca.transceive(
                    new byte[]{
                            (byte) 0xA2, // WRITE
                            (byte) page,
                            (byte) 0x04,
                            (byte) 0x00,
                            (byte) 0x00,
                            (byte) 0x00 // 保護開始ページ 0h で NXP TagInfo App でもダンプ不能に
                    }
            );
            Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

        } catch (Exception e) {
            Log.d(TAG, "NTAG WRITE err: page=" + page + " :" + e.toString());
        }
        closeNfcA(mNfca);

        if (mNextOfs == 0) {
            mHandler.sendEmptyMessage(MSG_ENDW);
        } else {
            if (mTagCount <= TAGCOUNT_MAX) {
                mHandler.sendEmptyMessage(MSG_SETNEXTTAG);
            } else {
                mHandler.sendEmptyMessage(MSG_TAGCOUNTOVER);
            }
        }
    }

    // パスワード解除＋タグ初期化
    private void releaseTag() {
        Message msg = new Message();
        msg.what = MSG_QUERYUSER;
        msg.obj = "タグのパスワードを解除しデータを抹消します。よろしいですか？";
        msg.arg1 = MSG_DO_RELEASE;
        mHandler.sendMessage(msg);
    }

    private void releaseTag1() {
        Log.d(TAG, "releaseTag1");
        mHandler.sendEmptyMessage(MSG_PROGRESS);
        int page = 0;
        byte[] res = null;

        if (connectNfcA(mNfca) != 0) {
            mHandler.sendEmptyMessage(MSG_ERROR);
            return;
        }
        boolean authOk = false;
        // パスワード保護状況をチェック
        int sts = isPasswordProtectedTag(mNfca);
        if (sts == 0) {
            authOk = true;
        }
        // パスワード保護あり
        if (!authOk) {
            byte[] p = getPassword();
            if (p == null) {
                closeNfcA(mNfca);
                mHandler.sendEmptyMessage(MSG_NEEDAUTH);
                return;
            }
            // 認証要求
            sts = passwordAuth(mNfca, p);
            if (sts == 1) {
                authOk = true;
            }
            Log.d(TAG, "auth=" + authOk);
        }

        // 認証通過
        if (authOk) {
            try {
                // パスワード保護解除
                page = mNtagConfPage0; // config page 0
                res = mNfca.transceive(
                        new byte[]{
                                (byte) 0xA2, // WRITE
                                (byte) page,
                                (byte) 0x04,
                                (byte) 0x00,
                                (byte) 0x00,
                                (byte) 0xFF // 有効範囲超のページ指定で保護は無効となる
                        }
                );
                Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

                // Read 保護ビット解除 + パスワード試行上限回数の AUTHLIM を無効化
                page = mNtagConfPage0 + 1; // config page 1
                res = mNfca.transceive(
                        new byte[]{
                                (byte) 0xA2, // WRITE
                                (byte) page,
                                (byte) 0x00,// read protect=0,  AUTHLIM=0
                                (byte) 0x05,
                                (byte) 0x00,
                                (byte) 0x00
                        }
                );
                Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

                // PWD を初期値に
                page = mNtagConfPage0 + 2; // config page 2
                res = mNfca.transceive(
                        new byte[]{
                                (byte) 0xA2, // WRITE
                                (byte) page,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
                        }
                );
                Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

                // PACK を初期値に
                page = mNtagConfPage0 + 3; // config page 3
                res = mNfca.transceive(
                        new byte[]{
                                (byte) 0xA2, // WRITE
                                (byte) page,
                                0, 0, 0, 0
                        }
                );
                Log.d(TAG, "WRITE p" + page + " reslen=" + res.length + " res=" + bytesToHexString(res));

                // 全ユーザ領域を白紙化
                for (page = 0x04; page < mNtagTotalPage - 5; page++) {
                    res = mNfca.transceive(
                            new byte[]{
                                    (byte) 0xA2, // WRITE
                                    (byte) page,
                                    0, 0, 0, 0
                            }
                    );
                }
            } catch (IOException e) {
                Log.d(TAG, "NTAG  WRITE err: page=" + page + ": " + e.toString());
                mHandler.sendEmptyMessage(MSG_ERROR);
            }
        } else { // 認証 NG
            closeNfcA(mNfca);
            mHandler.sendEmptyMessage(MSG_NEEDAUTH);
            return;
        }
        closeNfcA(mNfca);
        mHandler.sendEmptyMessage(MSG_TAGINITDONE);
    }

    @Override
    public boolean handleMessage(Message msg) {
        int len = 0;
        switch (msg.what) {
            case MSG_PROGRESS:
                closeDialogs();
                mProgressDlg = new ProgressDialog(this);
                mProgressDlg.setMessage("処理中...");
                mProgressDlg.show();
                break;

            case MSG_CANCEL:
                closeDialogs();
                mTagCount = 0;
                mNextOfs = 0;
                mRadioRead.setEnabled(true);
                mRadioWrite.setEnabled(true);
                mRadioInit.setEnabled(true);
                break;

            case MSG_ERASETEXT:
                mTextData.setText("");
                break;

            case MSG_SETNEXTTAG:
                showDialogMessageCANCEL(this, "次のタグを近づけて下さい");
                break;

            case MSG_ENDW:
                closeDialogs();
                mRadioRead.setEnabled(true);
                mRadioWrite.setEnabled(true);
                mRadioInit.setEnabled(true);
                showDialogMessageOK(this, "書き込みを終了しました", false);
                break;
            case MSG_NEEDAUTH:
                closeDialogs();
                showDialogMessageOK(this, "パスワードを正しく指定して下さい", false);
                break;
            case MSG_DATACHANGED:
                String s = mTextData.getText().toString();
                if (s.length() > 0) {
                    try {
                        byte[] b = s.getBytes(CHARSET);
                        len = b.length;
                    } catch (UnsupportedEncodingException e) {
                        //
                    }
                }
                //mTextData.setSelection(0);
                mDataLength.setText(len + " byte");
                break;

            case MSG_TAGINITDONE:
                closeDialogs();
                showDialogMessageOK(this, "タグのパスワードを解除しデータを初期化しました", false);
                break;

            case MSG_ANOTHER_PWD:
                closeDialogs();
                showDialogMessageOK(this, "このタグは異なるパスワードで保護されています。解除してから使用して下さい", false);
                break;

            case MSG_TAGCOUNTOVER:
                closeDialogs();
                showDialogMessageOK(this, "タグセットの最大枚数に達しました", false);
                mTagCount = 0;
                mNextOfs = 0;
                break;

            case MSG_ISNOTTARGET:
                closeDialogs();
                showDialogMessageOK(this, "対象外のタグです", false);
                break;

            case MSG_QUERYUSER:
                closeDialogs();
                String query = (String) msg.obj;
                mNext = msg.arg1;
                closeDialogs();
                showQueryDialog(this, query);
                break;

            case MSG_YES:
                if (mNext != -1) {
                    if (mNext == MSG_DO_READNEXT) {
                        mTagCount = 0;
                    }
                    doIt(mNext);
                }
                break;

            case MSG_NO:
                if (mNext == MSG_DO_READNEXT) {
                    mHandler.sendEmptyMessage(MSG_SHOWDATA);
                }
                mNext = -1;
                break;

            case MSG_SHOWUI:
                closeDialogs();
                mRadioWrite.setEnabled(true);
                mRadioWrite.setChecked(true);
                mRadioRead.setEnabled(false);
                mRadioInit.setEnabled(true);
                mPassword.setEnabled(true);
                mPassword.setVisibility(View.VISIBLE);
                mTextData.setVisibility(View.VISIBLE);
                mDataLength.setText(mTextData.getText().length() + " byte");
                break;

            case MSG_EMPTYTEXT:
                showDialogMessageOK(this, "テキストが入力されていません", false);
                break;

            case MSG_SHOWDATA:
                closeDialogs();
                if (msg.obj != null) {
                    mRadioRead.setEnabled(true);
                    mRadioWrite.setEnabled(true);
                    mRadioInit.setEnabled(true);
                    mPassword.setEnabled(true);
                    mPassword.setVisibility(View.VISIBLE);
                    mTextData.setVisibility(View.VISIBLE);
                    mTextData.setText(mTextData.getText().toString() + msg.obj);
                }
                if (mTagCount == 0) {
                    showDialogMessageOK(this, "読み込みを完了しました", false);
                } else {
                    showDialogMessageCANCEL(this, "記録ずみの " + (mTagCount + 1) + "枚めのタグを近づけて下さい");
                }
                break;

            case MSG_SUCCESS:
                closeDialogs();
                showDialogMessageOK(this, "正常に終了しました", false);
                break;

            case MSG_ERROR:
                closeDialogs();
                showDialogMessageOK(this, "エラーが発生しました", false);
                break;
        }
        return true;
    }

    private int connectNfcA(NfcA nfca) {
        try {
            nfca.connect();
        } catch (IOException e) {
            Log.d(TAG, "connectNfcA err: " + e.toString());
            return -1;
        }
        return 0;
    }

    private int closeNfcA(NfcA nfca) {
        if (nfca == null) {
            return 0;
        }
        if (nfca.isConnected()) {
            try {
                nfca.close();
            } catch (IOException e) {
                Log.d(TAG, "closeNfcA err: " + e.toString());
                return -1;
            }
        }
        return 0;
    }

    // 当該 NTAG21x タグのページ数を返す: NTAG21x 以外なら -1 を返す
    private int getNtagPageCount(Tag tag) {
        byte[] idArray = tag.getId();
        String uid = bytesToHexString(idArray);

        int nTagTotalPage = -1;
        boolean isMifareUL = false, isNfcA = false;
        String[] techs = tag.getTechList();
        for (int i = 0; i < techs.length; i++) {
            //Log.d(TAG, "tech=" + techs[i]);
            if (techs[i].equals(MifareUltralight.class.getName())) {
                isMifareUL = true;
            } else if (techs[i].equals(NfcA.class.getName())) {
                isNfcA = true;
            }
        }
        if (!(isNfcA && isMifareUL)) {
            return -1;
        }
        NfcA nfca = NfcA.get(tag);
        if (connectNfcA(nfca) != 0) {
            return -1;
        }
        // NTAG 種別取得
        try {
            byte[] res = nfca.transceive(new byte[]{
                    (byte) 0x60, // GET_VERSION
            });
            Log.d(TAG, "mNfcA GET_VERSION reslen=" + res.length + " res=" + bytesToHexString(res));
            if (res.length == 8) {
                if (res[0] == 0x00 && res[1] == 0x04 &&
                        res[2] == 0x04 && res[3] == 0x02) {
                    byte val = res[6];
                    if (val == 0x0F) {
                        nTagTotalPage = NTAG213_TOTALPAGE;
                    } else if (val == 0x11) {
                        nTagTotalPage = NTAG215_TOTALPAGE;
                    } else if (val == 0x13) {
                        nTagTotalPage = NTAG216_TOTALPAGE;
                    }
                }
            }
        } catch (IOException e) {
            Log.d(TAG, "NTAG GET_VERSION err:" + e.toString());
            closeNfcA(nfca);
            return -1;
        }
        if (!(nTagTotalPage == NTAG213_TOTALPAGE ||
                nTagTotalPage == NTAG215_TOTALPAGE ||
                nTagTotalPage == NTAG216_TOTALPAGE)) {
            Log.d(TAG, "is not NTAG21x");
            closeNfcA(nfca);
            return -1;
        }
        closeNfcA(nfca);
        return (int) nTagTotalPage;
    }

    // パスワード保護有無を判定  1:保護有効 0:保護なし -1:エラー
    private int isPasswordProtectedTag(NfcA nfca) {
        if (!nfca.isConnected()) {
            return -1; // エラー
        }
        // Config page 0 を read
        try {
            int page = mNtagConfPage0; // config page 0
            byte[] res = mNfca.transceive(
                    new byte[]{
                            (byte) 0x30, // NTAG READ
                            (byte) page,
                    }
            );
            // byte -> int
            int val = ByteBuffer.wrap(new byte[]{0, 0, 0, res[3]}).getInt();
            //Log.d(TAG, "isPasswordProtectedTag res[3]=" + val + " mNtagTotalPage=" +mNtagTotalPage);
            // readable かつ AUTH0 が実在ページ範囲超ならパスワード保護なし
            if (val >= mNtagTotalPage) {
                return 0;
            }
        } catch (IOException e) {
            Log.d(TAG, "isPwdProtectedTag READ err:" + e.toString());
        }
        return 1;
    }

    // パスワード認証要求  1:認証通過 0:認証 NG 負値:エラー
    private int passwordAuth(NfcA nfca, byte[] pwd) {
        if (!nfca.isConnected()) {
            return -1; // エラー
        }
        if (pwd == null || pwd.length != 4) {
            return -2; // エラー
        }
        // 認証要求
        try {
            byte[] res = mNfca.transceive(
                    new byte[]{
                            (byte) 0x1B, // NTAG PWD_AUTH
                            pwd[0], pwd[1], pwd[2], pwd[3]
                    }
            );
            Log.d(TAG, "NTAG PWD_AUTH reslen=" + res.length + " res=" + bytesToHexString(res));
            if (res.length == 2) {
                return 1; // OK
            }
        } catch (IOException e) {
            Log.d(TAG, "passwordAuth PWD_AUTH err:" + e.toString());
        }
        return 0; // NG;
    }

    private String getTagId(Tag tag) {
        if (tag == null) {
            return "";
        }
        byte[] b = tag.getId();
        return "ID:" + bytesToHexString(b);
    }

    private void closeDialogs() {
        if (mProgressDlg != null) {
            mProgressDlg.dismiss();
            mProgressDlg = null;
        }
        if (mDlg != null) {
            mDlg.dismiss();
            mDlg = null;
        }
    }

    private void showDialogMessageCANCEL(Context ctx, String msg) {
        mDlg = new AlertDialog.Builder(ctx).setTitle(getTagId(mTag))
                .setMessage(msg)
                .setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        mHandler.sendEmptyMessage(MSG_CANCEL);
                    }
                }).show();
    }

    private void showDialogMessageOK(Context ctx, String msg, final boolean bFinish) {
        new AlertDialog.Builder(ctx).setTitle(getTagId(mTag))
                .setMessage(msg)
                .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        if (bFinish) {
                            finish();
                        }
                    }
                }).show();
    }

    private void showQueryDialog(Context ctx, String msg) {
        mDlg = new AlertDialog.Builder(ctx).setTitle(getTagId(mTag))
                .setMessage(msg)
                .setPositiveButton("YES", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        mHandler.sendEmptyMessage(MSG_YES);
                        mDlg = null;
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        mHandler.sendEmptyMessage(MSG_NO);
                        mDlg = null;
                    }
                }).show();
    }

    private String bytesToHexString(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return new String(sb);
    }

    // 文字列を gzip 圧縮し結果を byte 配列で返す. 10 バイトの gzip ヘッダは除去
    private byte[] gzipPackString(String str) {
        //Log.d(TAG, "gzip mNtagTotalPage=" + mNtagTotalPage);
        int usableBytes = mNtagTotalPage * 4 - NTAG_UNUSABLE_BYTES - APP_HEADER_LENGTH;
        //Log.d(TAG, "usableBytes=" + usableBytes);
        byte[] packed = null;
        byte[] data = null;
        int cnt = 0, len = 0;
        // 領域に収まるまで一文字ずつ削りながら圧縮を試行
        do {
            String s = str.substring(0, str.length() - cnt++);
            try {
                data = s.getBytes(CHARSET);
            } catch (UnsupportedEncodingException e) {
                Log.d(TAG, "getBytes err=" + e.toString());
            }
            len = data.length;
            byte[] b = new byte[len];
            System.arraycopy(data, 0, b, 0, len);
            ByteArrayOutputStream compressBaos = new ByteArrayOutputStream();
            try (
                    OutputStream gzip = new GZIPOutputStream(compressBaos)) {
                try {
                    gzip.write(b);
                } catch (IOException e) {
                    Log.d(TAG, "gzipPack write err=" + e.toString());
                }
            } catch (Exception e) {
                Log.d(TAG, "gzipPack err=" + e.toString());
            }
            packed = compressBaos.toByteArray();
        } while ((packed.length - GZIP_HEADER_LENGTH) > usableBytes);

        Log.d(TAG, "packed.length - GZIP_HEADER_LENGTH)=" + (packed.length - GZIP_HEADER_LENGTH) +
                " usableBytes=" + usableBytes);

        // gzip ヘッダ 10バイトを除去
        len = packed.length - GZIP_HEADER_LENGTH;
        byte[] r = new byte[len];
        System.arraycopy(packed, GZIP_HEADER_LENGTH, r, 0, len);
        return r;
    }

    // gzipPackString() による 圧縮データを unpack し結果を String で返す
    private String gzipUnpackString(byte[] packed) {
        String s = "";
        // gzip ヘッダ 10バイトを先頭へ付与
        byte[] d = new byte[GZIP_HEADER_LENGTH + packed.length];
        System.arraycopy(GZIP_HEADER, 0, d, 0, GZIP_HEADER_LENGTH);
        System.arraycopy(packed, 0, d, GZIP_HEADER_LENGTH, packed.length);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (InputStream gzip = new GZIPInputStream(new ByteArrayInputStream(d))) {
            int b;
            while ((b = gzip.read()) != -1) {
                os.write(b);
            }
        } catch (IOException e) {
            Log.d(TAG, "gzipUnpack read err=" + e.toString());
        }
        byte[] decompressed = os.toByteArray();
        try {
            s = new String(decompressed, CHARSET);
            //Log.d(TAG, "gzip decompress size=" + decompressed.length + " str=" + s);
        } catch (UnsupportedEncodingException e) {
            //
        }
        return s;
    }

    // UI からパスワード文字列を取得し CRC32 値を byte 配列で返す
    private byte[] getPassword() {
        String pwd = mPassword.getText().toString();
        //Log.d(TAG, "getPassword pwd=" + pwd);
        if (pwd.length() <= 0) {
            return null;
        }
        byte[] b = pwd.getBytes();
        CRC32 crc = new CRC32();
        crc.reset();
        crc.update(b, 0, b.length);
        long crcVal = crc.getValue();
        //Log.d(TAG, "crc=" + Long.toHexString(crcVal));
        byte crcData[] = new byte[4];
        for (int i = 0; i < 4; i++) {
            crcData[i] = (byte) (crcVal >> (24 - i * 8));
        }
        //Log.d(TAG, "crc=" + bytesToHexString(crcData));
        return crcData;
    }
}