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
public class URLScanner201805 {

	/**
	 * @param args 引数としてファイルを渡す。
	 * @throws IOException 
	 * @throws InterruptedException
	 */
	public static void main(String[] args) throws IOException, InterruptedException {
		// TODO Auto-generated method stub
		if (args.length < 1) {
			System.out.println("引数がありません。");
			return;
		}
		
		// 実行時間計測
		long start = System.currentTimeMillis();
		
		// proxy経由でインターネットにアクセスする場合、使用する設定。
		
		System.setProperty("http.proxyHost",     "proxy-mon.ns-sol.co.jp");
		System.setProperty("http.proxyPort",     "8000");
		System.setProperty("https.proxyHost",     "proxy-mon.ns-sol.co.jp");
		System.setProperty("https.proxyPort",     "8000");
		System.setProperty("http.nonProxyHosts", "localhost");
		
		
		String path_name = args[0];
		ArrayList<File> file_list = listUpScanFiles(path_name);
		
		String scan_result_name = null;
		String input_file_name = null;
		
		// scanするinput file name
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmm");
		String date_str = sdf.format(date);
		
		if ((new File(path_name)).isFile()) {
			int i = path_name.lastIndexOf("\\");
			path_name = path_name.substring(0, i);
		}
		
		String scan_input_file_name = path_name.concat("\\scan_input_" + date_str + ".txt");
		
		StringBuffer sb = new StringBuffer();
		

		for (int i = 0; i < file_list.size(); i++) {
			input_file_name = file_list.get(i).getAbsolutePath();			
			sb = addToSB(input_file_name, sb);
			
		}
		
		FileWriter fw = null;
		try {
			fw = new FileWriter(new File(scan_input_file_name), true);
			if (fw != null) {
				fw.write(sb.toString());
				fw.close();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("URLScanner ファイル出力エラー");
			
		}
		
		// スキャン
		scan_result_name = scan(scan_input_file_name);
		
		// urlリストファイル更新
		updateURLList(scan_input_file_name, scan_result_name);
		
		if (file_list != null) {
			file_list.clear();
		}
		
		// 実行時間計測
		long end = System.currentTimeMillis();
		System.out.println("実行時間 : " + (end - start) + "ms");
	}
	
	public static StringBuffer addToSB(String input_file_name, StringBuffer sb) {
		
		if (input_file_name == null) {
			System.out.println("ファイルが指定されていません。makeInputFile");
			return null;
		}
		
		// スキャンするURL一覧ファイルを開く。ファイル名は、引数として渡される。
		File file = new File(input_file_name);
		BufferedReader br = null;
		String str = null;
		
		try {
			br = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("ファイルが見つかりません。#2");
			return null;
			//e1.printStackTrace();
		}
		
		int exist_i = 0;
		
		try {
			while((str = br.readLine()) != null) {
				// "スペース"、"wl_"、"#"、"スペース#"で始まる場合は、次の行へいく。
				if (str.equals("") || str.startsWith("wl_") || str.startsWith("#") || str.startsWith("﻿#")) {
					continue;
				}
				
				//重複排除
				exist_i = sb.indexOf(str);
				
				if (exist_i < 0) {
					sb.append(str);
					sb.append("\r\n");
				}
				
				/** 重複排除なし
				sb.append(str);
				sb.append("\r\n");
				*/
			}
			
			if (br != null) {
				br.close();
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("URLScanner ファイル入力エラー");
			
		}
		
		return sb;
	}
	
	public static String scan(String url_file_name) {
		// VirusTotal APIキーを設定する。
		VirusTotalAPI virusTotal = VirusTotalAPI.configure("f10106d812d4c3fcb2179658a1f5c780459fca645184e169f4c665126f19b881");
		
		if (url_file_name == null) {
			System.out.println("ファイルが指定されていません。");
			return null;
		}
		
		int bslash_i = url_file_name.lastIndexOf("\\");
		String head_str = url_file_name.substring(0, bslash_i);
		
		File output_dir = new File(head_str);
		
		if (!output_dir.exists()) {
			if (!output_dir.mkdirs()) {
				return null;
			}
		}
		
		// スキャンするURL一覧ファイルを開く。ファイル名は、引数として渡される。
		File file = new File(url_file_name);
		BufferedReader br = null;
		
		
		String output_file_name = url_file_name.replace("scan_input", "scan_result");
		
		File output_file = new File(output_file_name);
		FileWriter fw = null;
		try {
			fw = new FileWriter(output_file, true);
		} catch (IOException e) {
			System.out.println("ファイルが見つかりません。#3");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// スキャン成否結果を出力したURL総数
		int total_url_num = 0;
		
		try {
			br = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("ファイルが見つかりません。#4");
			return null;
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
				if (str.equals("")) {
					continue;
				}
				
				// デバッグ用System.out
				System.out.println(str);
				
				// URLを4件ずつファイルに書き出して、リスト"urls"に入れる。
				if ((idx_list >= 0) && (idx_list < 4)) {
					fw.write("");
					fw.write(idx_list + " : " + str + "\r\n");
					fw.flush();
					
					// strがIPアドレスの場合、URLを作成する時、java.net.MalformedURLException: no protocol: 195.xx.xx.xxxとなる。
					if (str.startsWith("http") == false) {
						str = "http://" + str;
					}
					
					url = new URL(str);
					urls[idx_list] = url;
					
				}
				
				// リスト"urls"にURLが4件入ったら、VirusTotalでスキャンする。
				if (idx_list == 3) {
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
					
					idx_list = -1;
					
				}
				//repeat_count = repeat_count + 1;
				idx_list++;
				
				// VirusTotalのクエリは4件/分までなので、1件ごとに15秒sleepする。
				Thread.sleep(15*1000);
			}
		} catch (InvalidURLException e) {
			// TODO Auto-generated catch block
			System.out.println("無効なURLです。");
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			System.out.println("無効な形式のURLです。");
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイル入出力に失敗しました。");
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if ((idx_list >= 1) && (idx_list < 4)) {
			// リストURL[]に入れるURL数が4より小さい場合、URL数のサイズのリスト"urls2"を作成する。
			URL[] urls2 = new URL[idx_list];
			for (int j = 0; j < idx_list; j++) {
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
				System.out.println("無効なURLです。");
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("ファイルの出力に失敗しました。#5");
				e.printStackTrace();
			}
			
		}
		
		try {
			if (br != null) {
				br.close();
			}
			
			fw.write("\r\n");
			fw.write("\r\n");
			fw.write(" URL総数 : " + total_url_num + "件\r\n");
			fw.write("\r\n");
			
			if (fw != null) {
				fw.close();
			}
			
			return output_file_name;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイル書き込みに失敗しました。#2");
			e.printStackTrace();
		}
		
		return output_file_name;
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
	    
	    try (final Stream<Path> pathStream = Files.walk(Paths.get(baseDir), 1)) {
	    	pathStream
	    		.map(path -> path.toFile())
	    		.filter(file -> !file.isDirectory() && file.getName().startsWith("wl_"))
	    		.forEach(fileList::add);
	    		
	    } catch (IOException e) {
	    	// TODO Auto-generated catch block
	    	e.printStackTrace();
	    }
		
		return (fileList);
		
	}
	
	// フォルダ以下のファイルをリストアップする。
	public static ArrayList<File> listUpScanFiles(String path_name) {
		ArrayList<File> file_list = new ArrayList<File>(100);
		
		// path_nameがファイル名の場合
		File path_name_file = new File(path_name);
		if (path_name_file.isFile()) {
			file_list.add(path_name_file);
			return file_list; 
		}
		
		// path_nameがディレクトリ名の場合
		ArrayList<File> dir_list = listUpDirs(path_name);
		ArrayList<File> tmp_list = null;
		
		for (int i = 0; i < dir_list.size(); i++) {
			path_name = dir_list.get(i).getAbsolutePath();

			
System.out.println("listup : " + path_name);
			tmp_list = listUpFiles(path_name);
			file_list.addAll(tmp_list);
			
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
	
	public static void writeToFile(FileWriter fw, List<URLScanMetaData> scanURLs) {
		scanURLs.stream().map((scanURL) -> {
			
			try {
				fw.write(" URL : " + scanURL.getUrl() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#3");
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Resource : " + scanURL.getResource() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#4");
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Scan Date : " + scanURL.getScanDate() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#5");
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Scan Id : " + scanURL.getScanId() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#6");
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Response Code : " + scanURL.getResponseCode() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#7");
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" Permalink : " + scanURL.getPermalink() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#8");
				e.printStackTrace();
			}
			
			return scanURL;
		}).map((scanURL) -> {
			try {
				fw.write(" VerboseMessage : " + scanURL.getVerboseMsg() + "\r\n");
				fw.flush();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("ファイル書き込みに失敗しました。#9");
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
				System.out.println("ファイル書き込みに失敗しました。#10");
				e.printStackTrace();
			}
			
		});
	}
	
	// スキャンに失敗したURLについて、url_listに印をつける。
	public static void updateURLList(String url_file_name, String scan_result_name) {
		// scanner_resultファイルを読み込む。
		if ((url_file_name == null) || (scan_result_name == null)) {
			return;
		}
		
		File scanner_result = new File(scan_result_name);
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
			url_file_name = tmp_str1 + "chkd_" + tmp_str2;
			
		} else {
			url_file_name = url_file_name + "_chkd";
			
		}
		
		File output_file = new File(url_file_name);
		FileWriter fw = null;
		
		try {
			fw = new FileWriter(output_file, false);
			fw.write("chkd_" + tmp_str2 + "\r\n");
			
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
			fw.write("\r\n");
			fw.write("\r\n");
			fw.write("　URL総数 : " + total_url_num + "件\r\n");
			fw.write("　スキャン成功数 : " + success_num + "件\r\n");
			fw.write("　スキャン失敗数 : " + error_num + "件\r\n");
			fw.write("\r\n");
			fw.close();
			
			if (br_result != null) {
				br_result.close();
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("ファイルの出力に失敗しました。#11");
			e.printStackTrace();
		}
		
	}

}
