/**
 * 
 */
package wl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import me.vighnesh.api.virustotal.InvalidURLException;
import me.vighnesh.api.virustotal.VirusTotalAPI;
import me.vighnesh.api.virustotal.dao.URLScanMetaData;
import me.vighnesh.api.virustotal.dao.URLScanReport;

/**
 * @author N21648
 * 使用する最終版。コマンドプロンプト用。
 *
 * VirusTotalにURLを送信してスキャンするためのクラス
 */
public class URLScannerBK {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws InterruptedException
	 */
	public static void main(String[] args) throws IOException, InterruptedException {
		// TODO Auto-generated method stub
		
		// proxy経由でインターネットにアクセスする場合、使用する設定。
		System.setProperty("http.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("http.proxyPort",     "8000");
		System.setProperty("https.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("https.proxyPort",     "8000");
		System.setProperty("http.nonProxyHosts", "localhost");
		
		// スキャン
		scan(args[0]);
		
		// urlリストファイル更新
		updateURLList(args[0]);
		
	}
	
	public static void scan(String url_file_name) {
		// VirusTotal APIキーを設定する。
		VirusTotalAPI virusTotal = VirusTotalAPI.configure("f10106d812d4c3fcb2179658a1f5c780459fca645184e169f4c665126f19b881");
		
		// スキャンするURL一覧ファイルを開く。ファイル名は、引数として渡される。
		File file = new File(url_file_name);
		BufferedReader br = null;
		//int repeat_count = 0;
		
		// VirusTotalでスキャンした結果をファイル"scanner_result.txt"に保存する。
		File output_file = new File("C:\\work\\whitelist\\03_部門\\全社共通\\03_評価結果\\scanner_result.txt");
		FileWriter fw = null;
		try {
			fw = new FileWriter(output_file, false);
		} catch (IOException e) {
			System.out.println("ファイルの出力に失敗しました。#1");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// スキャン成否結果を出力したURL総数
		int total_url_num = 0;
		
		try {
			br = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("入力ファイルが見つかりません。\n");
			return;
			//e1.printStackTrace();
		}
				
		int idx_list = 0;
		URL url = null;
		URL[] urls = new URL[4]; 
		String str = null;
		List<URLScanMetaData> scanURLs = null;
		List<URLScanMetaData> scanURLs2 = null;
		
		// URLを4件ずつリストURL[]に入れて、VirusTotalに渡す。
		// スキャン結果をファイルに書き出す。		
		try {
			while((str = br.readLine()) != null) {
				// デバッグ用System.out
				System.out.println(str);
				
				if (str.equals("")) {
					continue;
				}
				
				// URLを4件ずつファイルに書き出して、リスト"urls"に入れる。
				if ((idx_list > 0) && (idx_list <= 4)) {
					fw.write("");
					fw.write(idx_list-1 + " : " + str + "\r\n");
					fw.flush();
					
					// strがIPアドレスの場合、URLを作成する時、java.net.MalformedURLException: no protocol: 195.xx.xx.xxxとなる。
					if (str.startsWith("http") == false) {
						str = "http://" + str;
					}
					
					url = new URL(str);
					urls[idx_list-1] = url;
					
				}
				
				// リスト"urls"にURLが4件入ったら、VirusTotalでスキャンする。
				if (idx_list == 4) {
					scanURLs = virusTotal.scanURLs(urls);
					
					// スキャン結果をファイルに書き出す。
					//fw.write("-----SCAN META DATA-----" + repeat_count + "回目 \n");
					fw.write("-----SCAN META DATA-----\r\n");
					fw.flush();
					
					writeToFile(fw, scanURLs);
					
					// 出力URL総数
					total_url_num = total_url_num + scanURLs.size();
					
					// urlsリストを作り直す。
					urls = new URL[4];
					
					idx_list = 0;
					
				}
				//repeat_count = repeat_count + 1;
				idx_list++;
				
				// VirusTotalのクエリは4件/分までなので、1件ごとに15秒sleepする。
				Thread.sleep(15*1000);
			}
		} catch (InvalidURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイル入出力に失敗しました。\n");
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if ((idx_list >= 2) && (idx_list < 5)) {
			// リストURL[]に入れるURL数が4より小さい場合、URL数のサイズのリスト"urls2"を作成する。
			URL[] urls2 = new URL[idx_list-1];
			for (int j = 0; j < idx_list-1; j++) {
				urls2[j] = urls[j];
			}
			
			// リスト"urls2"をVirusTotalでスキャンする。
			try {
				scanURLs2 = virusTotal.scanURLs(urls2);
				
				// スキャン結果をファイルに書き出す。
				//fw.write("-----SCAN META DATA-----" + repeat_count + "回目 \n");
				fw.write("-----SCAN META DATA-----\r\n");
				fw.flush();
				
				writeToFile(fw, scanURLs2);
				
				// 出力URL総数
				total_url_num = total_url_num + scanURLs2.size();
				
			} catch (InvalidURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("ファイルの出力に失敗しました。#5");
				e.printStackTrace();
			}
			
		}
		
		try {
			br.close();
			
			fw.write("\r\n");
			fw.write(" URL総数 : " + total_url_num + "件\r\n");
			fw.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの出力に失敗しました。#2");
			e.printStackTrace();
		}
				
	}
	
	public static void writeToFile(FileWriter fw, List<URLScanMetaData> scanURLs) {
		scanURLs.stream().map((scanURL) -> {
			
			try {
				fw.write(" URL : " + scanURL.getUrl() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Resource : " + scanURL.getResource() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Scan Date : " + scanURL.getScanDate() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Scan Id : " + scanURL.getScanId() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Response Code : " + scanURL.getResponseCode() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Permalink : " + scanURL.getPermalink() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" VerboseMessage : " + scanURL.getVerboseMsg() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return scanURL;
		}).forEach((_item) -> {
			// デバッグ用System.out
			System.out.println("");
			try {
				fw.write("");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		});
	}
	
	// スキャンに失敗したURLについて、url_listに印をつける。
	public static void updateURLList(String url_file_name) {
		// scanner_resultファイルを読み込む。
		File scanner_result = new File("C:\\work\\whitelist\\03_部門\\全社共通\\03_評価結果\\scanner_result.txt");
		BufferedReader br_result = null;
		
		// url総数
		int total_url_num = 0;
		// スキャン失敗数
		int error_num = 0;
		// スキャン成功数
		int success_num = 0;
					
		// url_listを更新する。
		int bs_i = 0;
		
		bs_i = url_file_name.lastIndexOf("\\");
		String tmp_str1 = null;
		String tmp_str2 = null;
		
		if (bs_i > 0) {
			tmp_str1 = url_file_name.substring(0, bs_i + 1);
			tmp_str2 = url_file_name.substring(bs_i + 1);
			//url_file_name = tmp_str1 + "chkd_" + tmp_str2;
			url_file_name = "C:\\work\\whitelist\\03_部門\\全社共通\\03_評価結果\\chkd_" + tmp_str2;
			
		} else {
			url_file_name = url_file_name + "_chkd";
			
		}
		
		File output_file = new File(url_file_name);
		FileWriter fw = null;
		
		try {
			fw = new FileWriter(output_file, false);
			fw.write("chkd_" + tmp_str2 + "\r\n");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		try {
			br_result = new BufferedReader(new FileReader(scanner_result));
			String line = null;
			String url = null;
			
			int idx_list = 0;
			List<String> url_list = new ArrayList<String>();
			
			while((line = br_result.readLine()) != null) {
				for (int i = 0; i < 4; i++) {
					if (line.startsWith(i + " : ")) {
						url = line.substring(4);
						url_list.add(i, url);
						
					}
				}
				if(line.contains("SCAN META DATA")) {
					idx_list = 0;
				}
				
				if(line.contains("URL : ")) {
					//url = line.substring(7);
					idx_list = idx_list + 1;
					total_url_num = total_url_num + 1;
				}
				
				if (line.contains("Response Code : -1")) {
					fw.write("**" + url_list.get(idx_list - 1) + "\r\n");
					fw.flush();
					error_num = error_num + 1;
					
				} else if (line.contains("Response Code : 1")) {
					fw.write(url_list.get(idx_list - 1) + "\r\n");
					fw.flush();
					success_num = success_num + 1;
					
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの出力に失敗しました。#3");
			e.printStackTrace();
		}
		
		try {
			fw.write("\r\n");
			fw.write("　URL総数 : " + total_url_num + "件\r\n");
			fw.write("　スキャン成功数 : " + success_num + "件\r\n");
			fw.write("　スキャン失敗数 : " + error_num + "件\r\n");
			fw.close();
			br_result.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの出力に失敗しました。#4");
			e.printStackTrace();
		}
	}

}
