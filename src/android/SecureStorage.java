package com.crypho.plugins;

import java.lang.reflect.Method;

import android.util.Log;
import android.util.Base64;
import android.os.Build;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;
import javax.crypto.Cipher;

public class SecureStorage extends CordovaPlugin {
    private static final String TAG = "SecureStorage";

    private SharedPreferencesHandler PREFS;
    private String ALIAS;
    private int SUPPORTS_NATIVE_AES;
    private volatile CallbackContext initContext, secureDeviceContext;
    private volatile boolean initContextRunning = false;

    @Override
    public void onResume(boolean multitasking) {
        log.e(TAG, "Is secureDevice check");
        if (secureDeviceContext != null) {
            if (isDeviceSecure()) {
                secureDeviceContext.success();
            } else {
                secureDeviceContext.error("Device is not secure");
            }
            secureDeviceContext = null;
        }

        log.e(TAG, "Initializing the secure storage");
        if (initContext != null && !initContextRunning) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    initContextRunning = true;
                    try {
                        if (!RSA.isEntryAvailable(ALIAS)) {
                            RSA.createKeyPair(getContext(), ALIAS);
                        }
                        initContext.success(SUPPORTS_NATIVE_AES);
                    } catch (Exception e) {
                        Log.e(TAG, "Init failed :", e);
                        initContext.error(e.getMessage());
                    } finally {
                        initContext = null;
                        initContextRunning = false;
                    }
                }
            });
        }
    }

    private boolean isDeviceSecure() {
        Log.e(TAG, "Is device secure?");
        KeyguardManager keyguardManager = (KeyguardManager)(getContext().getSystemService(Context.KEYGUARD_SERVICE));
        try {
            Method isSecure = null;
            isSecure = keyguardManager.getClass().getMethod("isDeviceSecure");
            return ((Boolean) isSecure.invoke(keyguardManager)).booleanValue();
        } catch (Exception e) {
            return keyguardManager.isKeyguardSecure();
        }
    }

    @Override
    public boolean execute(String action, CordovaArgs args, final CallbackContext callbackContext) throws JSONException {
        android.util.Log.e(TAG, "execute: start");
        android.util.Log.e(TAG, "execute: init check");
        if ("init".equals(action)) {
            // 0 is falsy in js while 1 is truthy
            SUPPORTS_NATIVE_AES = Build.VERSION.SDK_INT >= 21 ? 1 : 0;
            ALIAS = getContext().getPackageName() + "." + args.getString(0);
            PREFS = new SharedPreferencesHandler(ALIAS + "_SS", getContext());

            if (!isDeviceSecure()) {
                String message = "Device is not secure";
                Log.e(TAG, message);
                callbackContext.error(message);
            } else if (!RSA.isEntryAvailable(ALIAS)) {
                initContext = callbackContext;
                unlockCredentials();
            } else {
                callbackContext.success(SUPPORTS_NATIVE_AES);
            }
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: set check");
        if ("set".equals(action)) {
            final String key = args.getString(0);
            final String value = args.getString(1);
            final String adata = args.getString(2);

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        JSONObject result = AES.encrypt(value.getBytes(), adata.getBytes());
                        byte[] aes_key = Base64.decode(result.getString("key"), Base64.DEFAULT);
                        byte[] aes_key_enc = RSA.encrypt(aes_key, ALIAS);
                        result.put("key", Base64.encodeToString(aes_key_enc, Base64.DEFAULT));
                        PREFS.store(key, result.toString());
                        callbackContext.success();
                    } catch (Exception e) {
                        Log.e(TAG, "Encrypt (RSA/AES) failed :", e);
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: get check");
        if ("get".equals(action)) {
            final String key = args.getString(0);
            String value = PREFS.fetch(key);
            if (value != null) {
                JSONObject json = new JSONObject(value);
                final byte[] encKey = Base64.decode(json.getString("key"), Base64.DEFAULT);
                JSONObject data = json.getJSONObject("value");
                final byte[] ct = Base64.decode(data.getString("ct"), Base64.DEFAULT);
                final byte[] iv = Base64.decode(data.getString("iv"), Base64.DEFAULT);
                final byte[] adata = Base64.decode(data.getString("adata"), Base64.DEFAULT);
                cordova.getThreadPool().execute(new Runnable() {
                    public void run() {
                        try {
                            byte[] decryptedKey = RSA.decrypt(encKey, ALIAS);
                            String decrypted = new String(AES.decrypt(ct, decryptedKey, iv, adata));
                            callbackContext.success(decrypted);
                        } catch (Exception e) {
                            Log.e(TAG, "Decrypt (RSA/AES) failed :", e);
                            callbackContext.error(e.getMessage());
                        }
                    }
                });
            } else {
                callbackContext.error("Key [" + key + "] not found.");
            }
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: decrypt_rsa check");
        if ("decrypt_rsa".equals(action)) {
            // getArrayBuffer does base64 decoding
            final byte[] decryptMe = args.getArrayBuffer(0);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] decrypted = RSA.decrypt(decryptMe, ALIAS);
                        callbackContext.success(new String (decrypted));
                    } catch (Exception e) {
                        Log.e(TAG, "Decrypt (RSA) failed :", e);
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: encrypt_rsa check");
        if ("encrypt_rsa".equals(action)) {
            final String encryptMe = args.getString(0);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] encrypted = RSA.encrypt(encryptMe.getBytes(), ALIAS);
                        callbackContext.success(Base64.encodeToString(encrypted, Base64.DEFAULT));
                    } catch (Exception e) {
                        Log.e(TAG, "Encrypt (RSA) failed :", e);
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: secureDevice check");
        if ("secureDevice".equals(action)) {
            secureDeviceContext = callbackContext;
            unlockCredentials();
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: remove check");
        //SharedPreferences interface
        if ("remove".equals(action)) {
            String key = args.getString(0);
            PREFS.remove(key);
            callbackContext.success();
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: store check");
        if ("store".equals(action)) {
            String key = args.getString(0);
            String value = args.getString(1);
            PREFS.store(key, value);
            callbackContext.success();
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: fetch check");
        if ("fetch".equals(action)) {
            String key = args.getString(0);
            String value = PREFS.fetch(key);
            if (value != null) {
                callbackContext.success(value);
            } else {
                callbackContext.error("Key [" + key + "] not found.");
            }
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: keys check");
        if ("keys".equals(action)) {
            callbackContext.success(new JSONArray(PREFS.keys()));
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: clear check");
        if ("clear".equals(action)) {
            PREFS.clear();
            callbackContext.success();
            android.util.Log.e(TAG, "execute: end");
            return true;
        }

        android.util.Log.e(TAG, "execute: end");
        return false;

    }

    private void unlockCredentials() {
        cordova.getActivity().runOnUiThread(new Runnable() {
            public void run() {
                Intent intent = new Intent("com.android.credentials.UNLOCK");
                startActivity(intent);
            }
        });
    }

    private Context getContext(){
        return cordova.getActivity().getApplicationContext();
    }

    private void startActivity(Intent intent){
        cordova.getActivity().startActivity(intent);
    }
}
