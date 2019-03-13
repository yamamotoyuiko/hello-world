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
import java.util.List;

import me.vighnesh.api.virustotal.VirusTotalAPI;
import me.vighnesh.api.virustotal.dao.URLScan;
import me.vighnesh.api.virustotal.dao.URLScanReport;

/**
 * @author N21648
 * 成功例
 * 使用するクラス最終版。コマンドプロンプト用。
 * VirusTotalのスキャン結果reportを取得して、ファイルに保存するためのクラス。
 * urlは、4つずつまで。
 *
 */
public class URLReporterBK {

	/**
	 * @param args
	 * @throws InterruptedException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws InterruptedException, IOException {
		// TODO Auto-generated method stub
		// proxy経由でインターネットに接続する場合、proxy設定をする。
		/**
		System.setProperty("http.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("http.proxyPort",     "8000");
		System.setProperty("https.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("https.proxyPort",     "8000");
		System.setProperty("http.nonProxyHosts", "localhost");
		*/
		
		report(args[0]);
		
	}
	
	public static void report(String input_file_name) {
		// VirusTotalのAPIキーをセットする。
		VirusTotalAPI virusTotal = VirusTotalAPI.configure("f10106d812d4c3fcb2179658a1f5c780459fca645184e169f4c665126f19b881");
		
		// VirusTotalでスキャンしたURLが保存されたファイルを開く。ファイル名は、引数で渡される。
		File input_file = new File(input_file_name);
		BufferedReader br = null;
		int repeat_count = 1;
		
		// VirusTotalのスキャン結果reportをファイル"reporter_result.txt"に書き出す。
		File output_file = new File("C:\\work\\ifilter_blacklist\\reporter_result.txt");
		// File output_file = new File(args[1]);
		FileWriter fw = null;
		
		try {
			fw = new FileWriter(output_file, false);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの入出力に失敗しました。#1");
			e.printStackTrace();
		}
		
		try {
			br = new BufferedReader(new FileReader(input_file));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("入力ファイルが見つかりません。\n");
			return;
			//e1.printStackTrace();
		}
		
		// URLリストのindex
		int i = 0;
		// 処理されたURL総数
		int total_url_num = 0;
		URL url = null;
		URL[] urls = new URL[4];
		String str = null;
		List<URLScanReport> urlReports = null;
		try {
			while((str = br.readLine()) != null) {
				
				if (str.isEmpty() == true) {
					break;
				} else if (str.startsWith("**")) {
					continue;
				}
				
				//デバッグ用System.out
				System.out.println(str);
				
				total_url_num = total_url_num + 1;
				
				// URLをリスト"urls"に入れて、ファイルに書き出す。
				if ((i > 0) && (i <= 4)) {
					
					fw.write(i-1 + " : " + str + "\r\n");
					fw.flush();
					
					if (str.startsWith("http") == false) {
						str = "http://" + str;
					}
					
					url = new URL(str);
					urls[i-1] = url;
					
				}
				
				if (i == 4) {
					
					// リスト"urls"に入れた4件のURLについて、VirusTotalのスキャン結果reportを取得する。
					urlReports = virusTotal.getURLsReport(urls);
					
					// VirusTotalのスキャン結果reportをファイルに書き出す。
					fw.write("-----URLS REPORT-----  " + repeat_count + "回目 \r\n");
					fw.flush();
					
					writeToFile(fw, urlReports);
					
					repeat_count = repeat_count + 1;
					i = 0;
					
					// VirusTotalのクエリは4件/分までなので、60秒間sleepする。
					try {
						Thread.sleep(60*1000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
				i++;
			}
			
			// URL一覧の最後に、URL数が4件未満になった場合、リスト"urls_short"に入れてVirusTotalに渡す。
			if ((i > 1) && (i < 5)) {
				
				URL[] urls_short = new URL[i-1];
				
				for (int j = 0; j < i-1; j++) {
					urls_short[j] = urls[j];
				}
				
				// VirusTotalのスキャン結果reportをファイルに書き出す。
				urlReports = virusTotal.getURLsReport(urls_short);
				
				//fw.write("url　listの長さ : " + (i-1) + "\r\n");
				fw.write("-----URLS REPORT----- " + repeat_count + "回目 \r\n");
				
				if (urlReports == null || urlReports.isEmpty()) {
					br.close();
					return;
				}
				
				writeToFile(fw, urlReports);
				
			}
			
			br.close();
			
			fw.write("\r\n");
			fw.write(" URL総数 : " + (total_url_num -1) + "件\n");
			fw.close();
			
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの入出力に失敗しました。#2");
			e1.printStackTrace();
		}
	}
	
	public static void writeToFile(FileWriter fw, List<URLScanReport> urlReports) {
		urlReports.stream().filter(urlReport -> (urlReport != null)).map((urlReport)-> urlReport.getScans()).filter(scans -> (scans != null && !scans.isEmpty())).map((scans)-> {
			
			try {
				fw.write("-----URL REPORT----- \r\n");
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイルの入出力に失敗しました。#3");
				e.printStackTrace();
			}
			
			return scans;
		}).filter(scans -> (scans != null && !scans.isEmpty())).map((scans)-> {
			
			return scans;
		}).filter(scans -> (scans != null && !scans.isEmpty())).forEach((scans) -> {
			scans.keySet().stream().filter(scan -> scan != null).forEach((scan) -> {
				URLScan report = scans.get(scan);
				
				try {
					fw.write(scan + "\t:" + report.getReport() + "\r\n");
					fw.flush();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					System.out.println("ファイルの入出力に失敗しました。#4");
					e.printStackTrace();
				}
				
			});
			
		});
		
		try {
			fw.write("-----URLS REPORT END----- \r\n");
			fw.flush();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの入出力に失敗しました。#5");
			e.printStackTrace();
		}
	}
}
