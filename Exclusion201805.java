/**
 * 
 */
package wl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
//import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.SequenceInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;


/**
 * @author Yuiko Yamamoto
 * Dedupli.javaとExclude.javaを一つにする。
 * 
 * 1次URLファイルを入力にする。
 * 1. 既存ホワイトリストを除外する。
 * 2. 社内URL、社内IPアドレスを除外する。
 * 
 */
public class Exclusion201805 {
	
	// 全社共通WLファイル名
	//static String all_wl_file_name = null;
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// 実行時間計測
		long start = System.currentTimeMillis();
		
		Exclusion201805 ex = new Exclusion201805();
		// 処理対象フォルダ
		String input_file_name = args[0];
		
		// 既存のWLファイル
		String wl_file_name = args[1];
			
		// 既存のBU毎WL除外後ファイル名
		String wl_output_file_name = null;
		
		// 処理対象1次URLファイル
		ArrayList<File> file_list = listUpFiles(input_file_name);
		
		if ((file_list == null) || (file_list.size() <= 0)) {
			System.out.println("ファイルが存在しません。\r\n");
			return;
		}
		
		// 指定フォルダ以下にあるURLリストファイルに、既存ホワイトリスト除外ツール、社内URL・社内IPアドレス除外ツールを実行する。
		
		for (int i = 0; i < file_list.size(); i++) {
			
			input_file_name = file_list.get(i).getAbsolutePath();
			
			if (input_file_name == null) {
				continue;
			}
			// 既存WLを除外する。
		    wl_output_file_name = ex.excludeWL(input_file_name, wl_file_name);
		}
		
		
		// 指定フォルダ以下にあるURLリストから重複排除する。
		/**
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmm");
		String date_str = sdf.format(date);
		String output_file_name = args[0] + "\\dedupli_" + date_str + ".txt";
		
		output_file_name = ex.dedupli(file_list, output_file_name);
		*/
		
		// 実行時間計測
		long end = System.currentTimeMillis();
		System.out.println("実行時間 : " + (end - start) + "ms");
		
		return;
		
	}
	
	// 既存ホワイトリストを除外するメソッド。
	public String excludeWL(String input_file_name, String wl_file_name) {
		if ((input_file_name == null) || (wl_file_name == null)) {
			// System.out.println("ファイルが見つかりません。");
			return null;
		}
		
		/**
		// 既存のBU毎ホワイトリストファイル
		ArrayList<File> wl_file = listUpFiles(wl_file_name);
		
		if ((wl_file != null) && (wl_file.size() > 0)) {
			wl_file_name = wl_file.get(0).getAbsolutePath();
		} else {
			wl_file_name = all_wl_file_name;
		}
		
		if (wl_file_name == null) {
			wl_file_name = all_wl_file_name;
		}
		*/
		
		// 対象1次URLファイル
		File input_file = new File(input_file_name);
		BufferedReader br_input = null;
		String line = null;
		
		try {
			br_input = new BufferedReader(new InputStreamReader(new FileInputStream(input_file), "UTF-8"));
			// br_input = new BufferedReader(new InputStreamReader(new FileInputStream(input_file), "MS932"));
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException ie) {
			ie.printStackTrace();
		}
		
		// 既存WLのBufferedReader
		BufferedReader br_wl = null;
		
		// 結果を2ファイルに保存する。 1.既存WL除外後のWL候補  2.除外したWLファイル
		String wl_output_file_name = null;
		String ex_wl_output_file_name = null;
		String tmp_str = null;
		
		int bs_i = input_file_name.lastIndexOf("\\");
		
		if (bs_i > 0) {
			// ファイル名
			tmp_str = input_file_name.substring(bs_i + 1);
			
			//output_file_name = input_file_name.substring(0, bs_i + 2) + "wl_" + tmp_str;
						
			wl_output_file_name = input_file_name.substring(0, bs_i) + "\\processed_" + tmp_str;
			ex_wl_output_file_name = input_file_name.substring(0, bs_i) + "\\ex_" + tmp_str;
			
		} else {
			wl_output_file_name = input_file_name + "_processed";
			ex_wl_output_file_name = input_file_name + "_ex";
		}
		
		File wl_output_file = new File(wl_output_file_name);
		File ex_wl_output_file = new File(ex_wl_output_file_name);
		
		PrintWriter wl_pw = null;
		PrintWriter ex_wl_pw = null;
		
		try {
			wl_pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(wl_output_file), "UTF-8")));
			ex_wl_pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(ex_wl_output_file), "UTF-8")));
			
			// 重複削除URLリストファイルの1行目に、"whitelist,new"を出力する。
			ex_wl_pw.write("whitelist,new\r\n");
			
		} catch (FileNotFoundException output_file_e) {
			output_file_e.printStackTrace();
		} catch (IOException output_file_ioe) {
			output_file_ioe.printStackTrace();
			
		}
		
		int wl_idx = 0;
		int input_idx = 0;
		
		String wl_str = null;
		boolean wl_bl = false;
		Pattern p_wl = null;
		Matcher m_wl = null;
		
		try {
			// 入力1次URLファイルの1行目見出行を出力する。
			if (br_input == null) {
				return null;
			}
			
			/**
			 * 先頭行がURL以外の場合必要。
			line = br_input.readLine();
			
			if ((line != null) && !(line.equals(""))) {
				ex_wl_pw.write(line + "\r\n");
				wl_pw.write(line + "\r\n");
			}
			*/
			
			while((line = br_input.readLine()) != null) {
				if (line.equals("")) {
					continue;
				}
				// 対象1次URLの件数
				input_idx = input_idx + 1;
				
				/**
				// 既存ホワイトリストと全社共通WLを連結する。
				if ((wl_file_name != null) && (all_wl_file_name != null) && (all_wl_file_name.equals(wl_file_name) == false)) {
					br_wl = new BufferedReader(new InputStreamReader(new SequenceInputStream((new FileInputStream(all_wl_file_name)), (new FileInputStream(wl_file_name))), "UTF-8"));
					
				} else if ((wl_file_name != null) && (all_wl_file_name != null) && (all_wl_file_name.equals(wl_file_name))) {
					br_wl = new BufferedReader(new FileReader(new File(wl_file_name)));
				} else if (wl_file_name != null){
					br_wl = new BufferedReader(new FileReader(new File(wl_file_name)));
				} else {
					if (wl_pw != null) {
						wl_pw.close();
					}
					if (ex_wl_pw != null) {
						ex_wl_pw.close();
					}
					
					return null;
				}
				
				*/
				
				br_wl = new BufferedReader(new FileReader(new File(wl_file_name)));
				
				// 既存WLに含まれるか調べる。
				while((wl_str = br_wl.readLine()) != null) {
					if (wl_str.equals("")) {
						continue;
					}
					
					// 正規表現用Pattern, Matcher作成。
					p_wl = Pattern.compile(wl_str);
					m_wl = p_wl.matcher(line);
					wl_bl = m_wl.find();
					
					if (wl_bl) {
						wl_idx = 0;
						// 除外するwlを出力する。
						ex_wl_pw.write(wl_str + "," + line + "\r\n");
						ex_wl_pw.flush();
						break;
					} else {
						wl_idx = wl_idx + 1;
						continue;
					}
				}
				if (wl_bl == false) {
					wl_pw.write(line + "\r\n");
					wl_pw.flush();
				}
				wl_bl = false;
				if (br_wl != null) {
					br_wl.close();
				}
			}
		} catch (IOException br_wl_ioe) {
			br_wl_ioe.printStackTrace();
		}
		
		try {
			if (br_input != null) {
				br_input.close();
			}
			if (br_wl != null) {
				br_wl.close();
			}
			if (wl_pw != null) {
				wl_pw.close();
			}
			if (ex_wl_pw != null) {
				ex_wl_pw.close();
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}

		return wl_output_file_name;
	}
	
	public String dedupli(ArrayList<File> file_list, String output_file_name) {
		String input_file_name = null;
		
        StringBuffer sb = new StringBuffer();
		
		for (int i = 0; i < file_list.size(); i++) {
			input_file_name = file_list.get(i).getAbsolutePath();
			
			sb.append(input_file_name);
			sb.append("\r\n");
			
			sb = addToSB(input_file_name, sb);
			
		}
		
		FileWriter fw = null;
		try {
			fw = new FileWriter(new File(output_file_name), true);
			if (fw != null) {
				fw.write(sb.toString());
				fw.close();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("URLScanner ファイル出力エラー");
			
		}
		
		return output_file_name;
	}
	
	// input_file_nameファイルの内容を重複排除して、StringBufferに追加する。
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
		int end_i = 0;
		String original_str = null;
		
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
				} else {
					end_i = sb.indexOf("\r\n", exist_i);
					original_str = sb.substring(exist_i, end_i);
					sb.append(str + ",重複," + original_str);
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

	// 社内URL、社内IPアドレスを除外するメソッド。
	public String excludeNS(String input_file_name, String output_file_name, String ns_file_name) {
		
		if ((input_file_name == null) || (output_file_name == null) || (ns_file_name == null)) {
			// System.out.println("ファイルが見つかりません。");
			return null;
		}
		
		// 対象となる1次URLファイル
		File input_file = new File(input_file_name);
		BufferedReader br_input = null;
		
		// 社内URL、社内IPアドレスファイル
		File ns_file = new File(ns_file_name);
		BufferedReader br_ns = null;
		
		// 2つの出力ファイル名を生成する。
		// 1.社内URL、社内IPアドレス除外後のWL候補ファイル
		PrintWriter pw = null;
		
		// 2.除外した社内URL、社内IPアドレスファイル
		String ns_output_file_name = null;
		PrintWriter ns_pw = null;
		
		int wl_i = input_file_name.lastIndexOf("\\wl_");
		int deli_i = input_file_name.lastIndexOf("\\");
		String tmp_str1 = output_file_name;
		String tmp_str2 = null;
		
		if (wl_i >= 0) {
			tmp_str2 = input_file_name.substring(wl_i + 4);
			output_file_name = tmp_str1 + "\\processed_" + tmp_str2;
			ns_output_file_name = tmp_str1 + "\\ex_ns_" + tmp_str2;
		} else if (deli_i >= 0) {
			tmp_str2 = input_file_name.substring(deli_i + 1);
			output_file_name = tmp_str1 + "\\processed_" + tmp_str2;
			ns_output_file_name = tmp_str1 + "\\ex_ns_" + tmp_str2;
			
		} else {
			return null;
		}
		
		File output_file = new File(output_file_name);
		File ns_output_file = new File(ns_output_file_name);
		
		try {
			// 入力ファイルを文字コード ANSIとして読み込む。
			//br_input = new BufferedReader(new InputStreamReader(new FileInputStream(input_file), "MS932"));
			// 入力ファイルを文字コード UTF-8として読み込む。
			br_input = new BufferedReader(new InputStreamReader(new FileInputStream(input_file), "UTF-8"));
			
			// 出力ファイルは、文字コードUTF-8とする。
			pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(output_file), "UTF-8")));
			
			ns_pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(ns_output_file), "UTF-8")));
			
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			System.out.println("ファイルが見つかりません。#1");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			System.out.println("エンコーディング・エラー");
		}
		
		String line = null;
		String ns_str = null;
		boolean ns_bl = false;
		
		try {
			
			line = br_input.readLine();
			
			if (line == null) {
				if (pw != null) {
					pw.close();
				}
				if (ns_pw != null) {
					ns_pw.close();
				}
				return null;
			}
			
			// 1行目を出力する。
			pw.write(line + "\r\n");
			
			ns_pw.write(line + "\r\n");
			
			
			while((line = br_input.readLine()) != null) {
				// 社内URLが含まれるかどうか調べる。
				br_ns = new BufferedReader(new InputStreamReader(new FileInputStream(ns_file), "UTF-8"));
				
				Pattern p_ns = null;
				Matcher m_ns = null;
				while((ns_str = br_ns.readLine()) != null) {
					if (ns_str.equals("")) {
						continue;
					}
					p_ns = Pattern.compile(ns_str.toString());
					m_ns = p_ns.matcher(line);
					
					ns_bl = m_ns.find();
					
					if (ns_bl) {
						ns_pw.write(line + "\r\n");
						break;
					}
					
				}
				
				// 社内URLが含まれなかった場合、行をWL候補ファイルに出力する。	
				if (ns_bl == false) {
					// 行を出力
					pw.write(line + "\r\n");
				}
				
				ns_bl = false;
				
				if (br_ns != null) {
					br_ns.close();
				}
			}
			
			if (br_input != null) {
				br_input.close();
			}
			
			if (pw != null) {
				pw.close();
			}
			if (ns_pw != null) {
				ns_pw.close();
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
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
	
	public BufferedReader concatAllWLFile(String all_wl_path, String bu_wl_path) {
		String all_wl_file_name = null;
		String bu_wl_file_name = null;
		BufferedReader br_wl = null;
		SequenceInputStream si = null;
		ArrayList<File> all_wl_list = null;
		ArrayList<File> bu_wl_list = null;
		
System.out.println("all_wl_path : " + all_wl_path);		
		// 全社共通WLファイル
		if (all_wl_path != null) {
			all_wl_list = listUpFiles(all_wl_path);
		}
		
		if ((all_wl_list != null) && (all_wl_list.size() > 0)) {
			all_wl_file_name = all_wl_list.get(0).getAbsolutePath();
		}
		
		// BU毎WLファイル
		if (bu_wl_path != null) {
			bu_wl_list = listUpFiles(bu_wl_path);
		}
		
		if ((bu_wl_list != null) && (bu_wl_list.size() > 0)) {
			bu_wl_file_name = bu_wl_list.get(0).getAbsolutePath();
		}
		
		try {
			si = new SequenceInputStream(new FileInputStream(all_wl_file_name), new FileInputStream(bu_wl_file_name));
			br_wl = new BufferedReader(new InputStreamReader(si));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			System.out.println("既存WLファイルが見つかりません。");
		}
		
		return br_wl;
	}
	
}
