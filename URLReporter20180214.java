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
public class URLReporter20180214 {

	/**
	 * @param args
	 * @throws InterruptedException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws InterruptedException, IOException {
		// TODO Auto-generated method stub
		// 実行時間計測
		long start = System.currentTimeMillis();
		
		// proxy経由でインターネットに接続する場合、proxy設定をする。
		
		System.setProperty("http.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("http.proxyPort",     "8000");
		System.setProperty("https.proxyHost",     "proxy.ns-sol.co.jp");
		System.setProperty("https.proxyPort",     "8000");
		System.setProperty("http.nonProxyHosts", "localhost");
		
		String path_name = args[0] + "\\03_部門";
		
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
		//File output_file = new File("C:\\work\\ifilter_blacklist\\reporter_result.txt");
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
		String date_str = sdf.format(date);
		
		int wl_i = input_file_name.lastIndexOf("\\01_WL");
		String head_str = input_file_name.substring(0, wl_i) + "\\03_評価結果";
		
		File output_dir = new File(head_str);
		
		if (!output_dir.exists()) {
			if (!output_dir.mkdirs()) {
				return;
			}
		}
		
		String output_file_name = head_str + "\\reporter_result_" + date_str + ".txt";
		
		File output_file = new File(output_file_name);
		FileWriter fw = null;
		
		try {
			fw = new FileWriter(output_file, true);
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
				} else if (str.startsWith("**")) {
					continue;
				}
				
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
			fw.write("\r\n");
			fw.write(" URL総数 : " + (total_url_num -1) + "件\r\n");
			fw.write("\r\n");
			fw.close();
			
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの入出力に失敗しました。#2");
			e1.printStackTrace();
		}
	}
	
	public static ArrayList<File> listUpInputFiles(String path_name) {
		ArrayList<File> dir_list = listUpDirs(path_name);
		ArrayList<File> file_list = new ArrayList<File>(100);
		ArrayList<File> tmp_list = null;
		
		for (int i = 0; i < dir_list.size(); i++) {
			path_name = dir_list.get(i).getAbsolutePath();
			if (path_name.contains("01_WL")) {
				
				tmp_list = listUpFiles(path_name);
				
				for (int j = 0; j < tmp_list.size(); j++) {
					String file_name = tmp_list.get(j).getName();
					
					if(file_name.contains("chkd_") == false) {
						tmp_list.remove(j);
						j = j - 1;
						
					}
					
				}
				
				file_list.addAll(tmp_list);
			}
		}
		
		return (file_list);
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
