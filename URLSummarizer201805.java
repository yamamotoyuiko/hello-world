/**
 * 
 */
package wl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;

/**
 * @author yuiko yamamoto
 * 使用するクラス最終版。
 * command line用。
 * VirusTotalスキャン結果から、Black URL判定した後、
 * Black URLでなかったURLについてnslookup, ping, http/https接続問い合わせを実行する。
 * URL.openConnection()の後、HttpURLConnection.connect()メソッド追加。
 */
public class URLSummarizer201805 {
	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		if (args.length < 1) {
			System.out.println("引数がありません。");
			return;
		}
		
		URLSummarizer201805 sum = new URLSummarizer201805();
		
		String path_name = args[0];
		
		ArrayList<File> file_list = sum.listUpReportFiles(path_name);
		
		String input_file_name = null;
		File input_file = null;
		
		for (int i = 0; i < file_list.size(); i++) {
			input_file_name = file_list.get(i).getAbsolutePath();
			if(input_file_name != null) {
				sum.evaluate(input_file_name);
			}
		}
		
	}
	
	// フォルダ内のファイルをリストアップするメソッド。
	public ArrayList<File> listUpReportFiles(String baseDir) {
		
		if (baseDir == null) {
			return null;
		}
		
		final ArrayList<File> fileList = new ArrayList<File>();
		
		File baseDirFile = new File(baseDir);
		if (!baseDirFile.exists()) {
			return (fileList);
		}
		
		try (final Stream<Path> pathStream = Files.walk(Paths.get(baseDir))) {
		    pathStream
		    	.map(path -> path.toFile())
		    	.filter(file -> !file.isDirectory() && file.getName().contains("reporter_result"))
		    	.forEach(fileList::add);
		    	
		} catch (IOException e) {
		    // TODO Auto-generated catch block
		    e.printStackTrace();
		}
		
		return (fileList);
			
	}
	
	// フォルダ内のフォルダをリストアップするメソッド。
	public ArrayList<File> listUpDirs(String baseDir) {
		if (baseDir == null) {
			return null;
		}
		
		final ArrayList<File> dirList = new ArrayList<File>();
		
		File baseDirFile = new File(baseDir);
	    if (!baseDirFile.exists()) {
	    	
	       	return (dirList);
	    }
	    
	    try (final Stream<Path> pathStream = Files.walk(Paths.get(baseDir))) {
	    	pathStream
	    		.map(path -> path.toFile())
	    		.filter(file -> file.isDirectory())
	    		.forEach(dirList::add);
	    		
	    } catch (IOException e) {
	    	// TODO Auto-generated catch block
	    	e.printStackTrace();
	    }
		
		return (dirList);
		
	}
	
	// フォルダ内のファイルをリストアップするメソッド。
	public ArrayList<File> listUpFiles(String baseDir) {
		if (baseDir == null) {
			return null;
		}
		
		final ArrayList<File> fileList = new ArrayList<File>();
		
		File baseDirFile = new File(baseDir);
		if (!baseDirFile.exists()) {
			return (fileList);
		}
		
		try (final Stream<Path> pathStream = Files.walk(Paths.get(baseDir))) {
		    pathStream
		    	.map(path -> path.toFile())
		    	.filter(file -> !file.isDirectory())
		    	.forEach(fileList::add);
		    	
		} catch (IOException e) {
		    // TODO Auto-generated catch block
		    e.printStackTrace();
		}
		
		return (fileList);
			
	}
	
	public void evaluate(String input_file_name) {
		// BLACK URL総数
		int black_url_num = 0;
		
		// WL候補数
		int wl_url_num = 0;
		
		// VirusTotalスキャン結果ファイル。
		File reporter_file = new File(input_file_name);
		BufferedReader br = null;
		
		// Black URL判定、nslookup, ping, http/https接続の結果を保存するファイル。
		
		int bslash_i = input_file_name.lastIndexOf("\\");
		String head_str = input_file_name.substring(0, bslash_i);
		
		File output_dir = new File(head_str);
		
		if (!output_dir.exists()) {
			if (!output_dir.mkdirs()) {
				return;
			}
		}
		
		String output_file_name = input_file_name.replace("reporter_result", "evaluation");
		
		File output_file = new File(output_file_name);
		FileWriter fw = null;
		
		String str = null;
		String[] url_list = new String[4];
		
		try {
			br = new BufferedReader(new FileReader(reporter_file));
			fw =  new FileWriter(output_file);
			
			int total_count = 0;
			int black_count = 0;
			int clean_count = 0;
			int unrated_count = 0;
			int suspicious_count = 0;
			int phishing_count = 0;
			int malicious_count = 0;
			int malware_count = 0;
			boolean dns_bln = false;
			//boolean ping_bln = false;
			//boolean http_bln = false;
			//boolean https_bln = false;
			int url_num = 0;
			boolean black_bln = false;
			
			while ((str = br.readLine()) != null) {
				
				if (str.contains("0 :")) {
					fw.write(str + "\r\n");
					fw.flush();
					url_list[0] = str.substring(4);
					
				} else if (str.contains("1 :")) {
					fw.write(str + "\r\n");
					fw.flush();
					url_list[1] = str.substring(4);
				} else if (str.contains("2 :")) {
					fw.write(str + "\r\n");
					fw.flush();
					url_list[2] = str.substring(4);
				} else if (str.contains("3 :")) {
					fw.write(str + "\r\n");
					fw.flush();
					url_list[3] = str.substring(4);
					
				} else if (str.contains("--URLS REPORT--")) {
					
					fw.write(str + "\r\n");
					fw.flush();
					url_num = 0;
					
				} else if (str.contains("URL REPORT") || str.contains("URLS REPORT END")) {
					
					black_count = phishing_count
									+ malicious_count + malware_count;
							
					total_count = clean_count + unrated_count + suspicious_count + black_count;
					
					if (total_count > 0) {
						black_bln = check_blacklist(black_count, total_count);
						
						if (black_bln == true) {
							fw.write(" BLACK URL \r\n");
							fw.flush();
							url_num = url_num + 1;
							black_url_num = black_url_num + 1;
						} else {
							fw.write(" WL CANDIDATE \r\n");
							fw.flush();
							dns_bln = nslookup_check(url_list[url_num], fw);
							//ping_bln = ping_check(url_list[url_num], fw);
							//http_bln = http_check(url_list[url_num], fw);
							//https_bln = https_check(url_list[url_num], fw);
							url_num = url_num + 1;
							wl_url_num = wl_url_num + 1;
						}
					}
						
					if (str.contains("URL REPORT")) {
						fw.write(url_num + " : " + str + "\r\n");
						fw.flush();
						// url_num = url_num + 1;
					} else if (str.contains("URLS REPORT END")) {
						fw.write(str + "\r\n");
						fw.flush();
						url_num = 0;
					}
					
					clean_count = 0;
					unrated_count = 0;
					suspicious_count = 0;
					phishing_count = 0;
					malicious_count = 0;
					malware_count = 0;
					black_count = 0;
					total_count = 0;
					
				} else if (str.contains("clean site")) {
					clean_count = clean_count + 1;
				} else if (str.contains("unrated site")) {
					unrated_count = unrated_count + 1;
				} else if (str.contains("suspicious site")) {
					suspicious_count = suspicious_count + 1;
				} else if (str.contains("phishing site")) {
					phishing_count = phishing_count + 1;
				} else if (str.contains("malicious site")) {
					malicious_count = malicious_count + 1;
				} else if (str.contains("malware site")) {
					malware_count = malware_count + 1;
				}
			}
			
			fw.close();
			
			// 評価を集計してまとめる。
			// 結果は、summary_yyyyMMddHHmm.txt
			summarize(output_file_name, black_url_num, wl_url_num);
			
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println(" ファイル reporter_result.txt が存在しません。 ");
			e1.printStackTrace();
		} catch (IOException ie) {
			System.out.println(" ファイル入出力に失敗しました。 #1");
			ie.printStackTrace();
		}
	}
	
	/** Black URL判定をするメソッド
	 * 
	 * @param black_count : 危険評価数 
	 * @param total_count : スキャン総数
	 * @return
	 */
    public static boolean check_blacklist(int black_count, int total_count) {
    	if (black_count > 0) {
    		return true;
    	}
    	return false;
    }
    
    /** DNS登録チェックメソッド
     * 
     * @param url : チェックするurl
     * @param fw : 結果を書き出すFileWriter
     * @return
     * @throws IOException
     */
    public static boolean nslookup_check(String url, FileWriter fw) throws IOException {
		String check_str = url;
		int i = 0;
		
		// check_str に "/" が含まれる場合、"/" までを check_str にする。
		if ((i = check_str.indexOf("/")) >= 0) {
			check_str = check_str.substring(0, i);
		}
		
		// check_str に ":" が含まれる場合、":" までを check_str にする。
		if ((i = check_str.indexOf(":")) >= 0) {
			check_str = check_str.substring(0, i);
		}
	
		try {
			fw.write("# dns check \r\n");
			
			Process p = new ProcessBuilder("nslookup", check_str).start();
			
			InputStream is = p.getInputStream();
			// InputStreamの文字コードを"MS932"にする。
			BufferedReader br = new BufferedReader(new InputStreamReader(is, "MS932"));
			
			String line = br.readLine();
			
			while (line != null) {
				if (line.contains("名前:")) {
					fw.write(line + "\r\n");
					line = br.readLine();
					
					if (line.contains("Address:") || line.contains("Addresses:")) {
						fw.write("  " + line + "\r\n");
					}
				}
				line = br.readLine();
			}
			fw.flush();
			br.close();
			p.destroy();	
		} catch (IOException ex) {
			System.out.println(" ファイル evaluation_yyyymmdd.txt への書き込みに失敗しました。 ");
			fw.write(" dns_check : IOException ");
			fw.write(" " + ex.getMessage() + " ");
			fw.flush();
			return false;
		}   
		return true;
	}
    
    /** ping疎通チェックメソッド
     * 
     * @param url : チェックするurl
     * @param fw : 結果を書き出すFileWriter
     * @return
     * @throws IOException
     */
	public static boolean ping_check(String url, FileWriter fw) throws IOException {
		// pingチェック
		InetAddress remote = null;
		
		String check_str = url;
		int i = 0;
		
		// check_str に "/" が含まれる場合、"/" までを check_str にする。
		if ((i = check_str.indexOf("/")) >= 0) {
			check_str = check_str.substring(0, i);
		}
		
		// check_str に ":" が含まれる場合、":" までを check_str にする。
		if ((i = check_str.indexOf(":")) >= 0) {
			check_str = check_str.substring(0, i);
		}
		
		try {
			fw.write("# ping check \r\n");
			// pingチェック
			remote = InetAddress.getByName(check_str);
			long start = System.currentTimeMillis();
			boolean isReachable = remote.isReachable(7000);
			long end = System.currentTimeMillis();
			long time = end - start;
			
			if (isReachable) {
				fw.write(" ping : " + isReachable + "\r\n");
			} else if (time >= 7000) {
				fw.write(" ping : Request timed out. \r\n");
			} else {
				fw.write(" ping : Destination net unreachable. \r\n");
			}
				
		} catch (IOException ie) {
			fw.write(" ping_check : IOException \r\n");
			fw.write(" " + ie.getMessage() + "\r\n");
			fw.flush();
			return false;
		}
		return true;
	}
	
	/** http接続チェックメソッド
	 * 
	 * @param url : チェックするurl
	 * @param fw : 結果を書き出すFileWriter
	 * @return
	 * @throws IOException
	 */
	public static boolean http_check(String url, FileWriter fw) throws IOException {
		// http openConnectionチェック
		HttpURLConnection conn = null;
		fw.write("# http check \r\n");
		
		try {
			// http 接続チェック
			url = "http://" + url;
			conn = (HttpURLConnection) new URL(url).openConnection();
			conn.setConnectTimeout(5000);
			conn.connect();
			
			fw.write(" response code : " + conn.getResponseCode() + "\r\n");
			fw.write(" response message : " + conn.getResponseMessage() + "\r\n");
			fw.flush();
			
		} catch (SocketTimeoutException ste) {
			fw.write(" http_check : SocketTimeoutException \r\n");
			fw.write(" " + ste.getMessage() + "\r\n");
			fw.flush();
			return false;
		} catch (IOException ie) {
			fw.write(" http_check : IOException \r\n");
			fw.write(" " + ie.getMessage() + "\r\n");
			fw.flush();
			return false;
		}
		conn.disconnect();
		return true;
	}
	
	/** https接続チェックメソッド
	 * 
	 * @param url : チェックするurl
	 * @param fw : 結果を書き出すFileWriter
	 * @return
	 * @throws IOException
	 */
	public static boolean https_check(String url, FileWriter fw) throws IOException {
		// https openConnectionチェック
		HttpsURLConnection conn_s = null;
		fw.write("# https check \r\n");
		
		try {
			// https 接続チェック
			url = "https://" + url;
			conn_s = (HttpsURLConnection) new URL(url).openConnection();
			conn_s.setConnectTimeout(5000);
			
			fw.write(" response code (s) : " + conn_s.getResponseCode() + "\r\n");
			fw.write(" response message (s) : " + conn_s.getResponseMessage() + "\r\n");
			fw.flush();
			
		} catch (IOException ie) {
			fw.write(" https_check : IOException \r\n");
			fw.write(" " + ie.getMessage() + "\r\n");
			fw.flush();
			
			return false;
		}
		return true;
	}
	
	/** 結果を集計するメソッド
	 * 
	 * @param eval_file : 評価結果ファイル
	 */
	public static void summarize(String evaluation_file_name, int black_url_num, int wl_url_num) {
		BufferedReader br = null;
		
		// 評価結果を書き出すファイル
		String output_file_name = evaluation_file_name.replaceAll("evaluation", "summary");
		File output_file = new File(output_file_name);
		
		BufferedWriter bw = null;
		
        try {
			bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(output_file), "UTF8"));
        	
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイル evaluation_yyyyMMddHHmm.txt が見つかりません。");
			e.printStackTrace();
		}
		
//		FileWriter fw = null;
		
        String str = null;
        String[] url_list = new String[4];
        int idx = 0;
        
		try {
			
			br = new BufferedReader(new FileReader(new File(evaluation_file_name)));
			
			// UTF8 BOM付きファイル作成
			bw.write(0xef);
			bw.write(0xbb);
			bw.write(0xbf);
			bw.write("idx" + "\t" + "URL" + "\t" + "BLACK/WHITE" + "\t" + "dns check" + "\t" + "CHECK" + "\r\n");
			
			while ((str = br.readLine()) != null) {
				
				if (str.contains("0 :") && !str.contains("URL REPORT")) {
					url_list[0] = str.substring(3);
					
				} else if (str.contains("1 :") && !str.contains("URL REPORT")) {
					url_list[1] = str.substring(3);
					
				} else if (str.contains("2 :") && !str.contains("URL REPORT")) {
					url_list[2] = str.substring(3);
					
				} else if (str.contains("3 :") && !str.contains("URL REPORT")) {
					url_list[3] = str.substring(3);
					
				}
				
				if (str.contains("0 : -----URL REPORT")) {
					
					bw.write(idx + "\t" + url_list[0]);
					bw.flush();
					
					idx++;
					
					str = writeResultToFile(br, bw);
					
					if ( str == null ) {
						break;
					}
			    }
				
				if (str.contains("1 : -----URL REPORT")) {
					bw.write(idx + "\t" + url_list[1]);
					bw.flush();
					
					idx++;
					
					str = writeResultToFile(br, bw);
					
					if ( str == null ) {
						break;
					}
				}
				
				if (str.contains("2 : -----URL REPORT")) {
					bw.write(idx + "\t" + url_list[2]);
					bw.flush();
					
					idx++;
					
					str = writeResultToFile(br, bw);
					
					if ( str == null ) {
						break;
					}
				}
				
				if (str.contains("3 : -----URL REPORT")) {
					bw.write(idx + "\t" + url_list[3]);
					bw.flush();
					
					idx++;
					
					str = writeResultToFile(br, bw);
					
					if ( str == null ) {
						break;
					}
				}
			}
			
			br.close();
			
			bw.flush();
			
			bw.write("\r\n");
			bw.write("\r\n");
			bw.write("評価対象 : " + (black_url_num + wl_url_num) + "件 \r\n");
			bw.write("BLACK URL : " + black_url_num + "件 \r\n");
			bw.write("WHITE LIST候補 : " + wl_url_num + "件 \r\n");
			bw.write("\r\n");
			
			bw.close();
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println(" 出力ファイルが見つかりません。 #1");
			System.out.println(e1.getMessage());
			
		} catch (IOException ie) {
			System.out.println(" IOException ファイル入出力エラー  #3");
			System.out.println(ie.getMessage());
		}
	}
	
	// 評価結果をファイルに出力するメソッド
	public static String writeResultToFile(BufferedReader br, BufferedWriter bw) {
		String str = null;
		try {
			while ((str = br.readLine()) != null && !str.contains("-----URL REPORT")
					&& !str.contains("URLS REPORT END")) {
				if (str.contains("BLACK URL") || str.contains("WL CANDIDATE")) {
					bw.write("\t");
					bw.write(str);
					continue;
				} else if (str.contains("# dns check")) {
					bw.write("\t");
					continue;
				}
				bw.write(str);
			}
			bw.write("\r\n");
			bw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println(" IOException ファイル入出力エラー  #4");
			e.printStackTrace();
		}
		return str;
	}
	
}
