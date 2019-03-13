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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

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
public class URLReporter {

	/**
	 * @param args
	 * @throws InterruptedException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws InterruptedException, IOException {
		// TODO Auto-generated method stub
		if (args.length < 1) {
			System.out.println("引数がありません。");
			return;
		}
		
		// 実行時間計測
		long start = System.currentTimeMillis();
		
		// proxy経由でインターネットに接続する場合、proxy設定をする。
		
		System.setProperty("http.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("http.proxyPort",     "8000");
		System.setProperty("https.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("https.proxyPort",     "8000");
		System.setProperty("http.nonProxyHosts", "localhost");
		
		String path_name = args[0] + "\\05_ホワイトリスト評価";
		
		ArrayList<File> file_list = listUpInputFiles(path_name);
		String reporter_input_file_name = null;
		
		for (int i = 0; i < file_list.size(); i++) {
			reporter_input_file_name = file_list.get(i).getAbsolutePath();
			
			report(reporter_input_file_name);
			
		}
		
		// 実行時間計測
		long end = System.currentTimeMillis();
		System.out.println("実行時間 : " + (end - start) + "ms");
		
	}
	
	public static void report(String input_file_name) {
		if (input_file_name == null) {
			System.out.println("ファイルが見つかりません。");
			return;
		}
		// VirusTotalのAPIキーをセットする。
		VirusTotalAPI virusTotal = VirusTotalAPI.configure("f10106d812d4c3fcb2179658a1f5c780459fca645184e169f4c665126f19b881");
		
		// VirusTotalでスキャンしたURLが保存されたファイルを開く。ファイル名は、引数で渡される。
		File input_file = new File(input_file_name);
		BufferedReader br = null;
		int repeat_count = 1;
		
		// VirusTotalのスキャン結果reportをファイル"reporter_result.txt"に書き出す。
		String output_file_name = input_file_name.replace("chkd_scan_input", "reporter_result");
		
		File output_file = new File(output_file_name);
		FileWriter fw = null;
		
		try {
			fw = new FileWriter(output_file);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの書き込みに失敗しました。#1");
			e.printStackTrace();
		}
		
		try {
			br = new BufferedReader(new FileReader(input_file));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("入力ファイルが存在しません。\n");
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
				} else if (str.startsWith("**") || str.startsWith("chkd_")) {
					continue;
				}
				
				total_url_num = total_url_num + 1;
				
				// URLをリスト"urls"に入れて、ファイルに書き出す。
				if ((i >= 0) && (i < 4)) {
					
					fw.write(i + " : " + str + "\r\n");
					fw.flush();
					
					if (str.startsWith("http") == false) {
						str = "http://" + str;
					}
					
					url = new URL(str);
					urls[i] = url;
					
				}
				
				if (i == 3) {
					
					// リスト"urls"に入れた4件のURLについて、VirusTotalのスキャン結果reportを取得する。
					urlReports = virusTotal.getURLsReport(urls);
					
					// VirusTotalのスキャン結果reportをファイルに書き出す。
					fw.write("-----URLS REPORT-----  " + repeat_count + "回目 \r\n");
					fw.flush();
					
					writeToFile(fw, urlReports);
					
					repeat_count = repeat_count + 1;
					i = -1;
					
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
			if ((i > 0) && (i < 4)) {
				
				URL[] urls_short = new URL[i];
				
				for (int j = 0; j < i; j++) {
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
			fw.write("\r\n");
			fw.write(" URL総数 : " + total_url_num + "件\r\n");
			fw.write("\r\n");
			fw.close();
			
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの入出力に失敗しました。#2");
			e1.printStackTrace();
		}
	}
	
	public static ArrayList<File> listUpInputFiles(String path_name) {
		if (path_name == null) {
			return null;
		}
		
		final ArrayList<File> fileList = new ArrayList<File>();
		
		File baseDirFile = new File(path_name);
		if (!baseDirFile.exists()) {
			return (fileList);
		}
		
		try (final Stream<Path> pathStream = Files.walk(Paths.get(path_name))) {
		    pathStream
		    	.map(path -> path.toFile())
		    	.filter(file -> !file.isDirectory() && file.getName().startsWith("chkd_"))
		    	.forEach(fileList::add);
		    	
		} catch (IOException e) {
		    // TODO Auto-generated catch block
		    e.printStackTrace();
		}
		
		return (fileList);
	}
	
	// フォルダ内のフォルダをリストアップするメソッド。
	public static ArrayList<File> listUpDirs(String baseDir) {
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
	public static ArrayList<File> listUpFiles(String baseDir) {
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
	
	public static void writeToFile(FileWriter fw, List<URLScanReport> urlReports) {
		urlReports.stream().filter(urlReport -> (urlReport != null)).map((urlReport)-> urlReport.getScans()).filter(scans -> (scans != null && !scans.isEmpty())).map((scans)-> {
			
			try {
				fw.write("-----URL REPORT----- \r\n");
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#3");
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
					System.out.println("ファイル書き込みに失敗しました。#4");
					e.printStackTrace();
				}
				
			});
			
		});
		
		try {
			fw.write("-----URLS REPORT END----- \r\n");
			fw.flush();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("ファイル書き込みに失敗しました。#5");
			e.printStackTrace();
		}
	}
}
