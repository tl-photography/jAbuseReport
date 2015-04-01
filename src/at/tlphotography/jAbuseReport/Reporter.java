/**
 * jAbuseReport
 *   
 * @author Thomas Leber
 * @version 0.1
 * 
 * This program collects abuse informations from GNU/Linux (tested with Debian 7.6) auth.log file to send to the Internet Service Provider 
 * Copyright (C) 2015 Thomas Leber
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 */

package at.tlphotography.jAbuseReport;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import org.apache.commons.net.whois.WhoisClient;

// TODO: Auto-generated Javadoc
/**
 * The Main Class.
 */
public class Reporter
{
	
	/** The log directory. */
	private static String										logDir;
	
	/** The standard name for the log files. */
	private static CharSequence							logNames	= "auth.log";
	
	/** The content. */
	private static HashMap<String, String>	content		= new HashMap<String, String>();
	
	/**
	 * The main method.
	 *
	 * @param args
	 *          the arguments
	 */
	public static void main(String[] args)
	{
		parseArguments(args);
		
		File[] directory = new File(logDir).listFiles(); // get the files in the dir
		
		for (File file : directory) // iterate over the file
		{
			if (!file.isDirectory() && file.getName().contains(logNames)) // if the file is not a dir and the name contains the logName string
			{
				if (file.getName().endsWith(".gz")) // is it zipped?
				{
					content.putAll(readGZFile(file));
				} else
				{
					content.putAll(readLogFile(file));
				}
			}
		}
		
		// save the mails to the log lines
		HashMap<String, ArrayList<LogObject>> finalContent = new HashMap<>();
				
		Iterator<Entry<String, String>> it = content.entrySet().iterator();
		while (it.hasNext())
		{
			Map.Entry<String, String> pair = it.next();
			String mail = whoIsLookUp(pair.getKey());
			
			if (finalContent.containsKey(mail))
			{
				finalContent.get(mail).add(new LogObject(pair.getValue()));
			} else
			{
				ArrayList<LogObject> temp = new ArrayList<LogObject>();
				temp.add(new LogObject(pair.getValue()));
				finalContent.put(mail, temp);
			}
			
			it.remove();
		}
		
		// sort them
		Iterator<Entry<String, ArrayList<LogObject>>> it2 = finalContent.entrySet().iterator();
		while (it2.hasNext())
		{
			Entry<String, ArrayList<LogObject>> pair = it2.next();
			Collections.sort(pair.getValue());
			println(pair.getKey() + " =");
			for (LogObject obj : pair.getValue())
			{
				println(obj.logContent);
			}
			
			println("\n");
			it2.remove();
		}
		
	}
	
	/**
	 * Whois look up.
	 *
	 * @param ip
	 *          the ip
	 * @return the string
	 */
	private static String whoIsLookUp(String ip)
	{
		String[] serverList = { "whois.ripe.net", "whois.lacnic.net", "whois.registro.br" };
		
		WhoisClient whois = new WhoisClient();
		try
		{
			for (String server : serverList)
			{
				whois.connect(server);
				String whoisData1 = whois.query(ip);
				StringBuilder result = new StringBuilder("");;
				result.append(whoisData1);
				
				String mail = extractEMail(result.toString());
				
				if (mail != null)
					return mail;
			}
			return "not found";
		} catch (SocketException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally
		{
			try
			{
				if (whois.isConnected())
					whois.disconnect();
			} catch (IOException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/**
	 * Extracts a eMail from string.
	 *
	 * @param string
	 *          the string
	 * @return the string
	 */
	private static String extractEMail(String string)
	{
		String EMAILADDRESS_PATTERN = "[a-zA-Z0-9_.-]*abuse[a-zA-Z0-9_.-]*@[a-zA-Z0-9_.-]*\\.[a-zA-Z0-9_.-]{2,4}";
		
		Pattern pattern = Pattern.compile(EMAILADDRESS_PATTERN);
		
		Matcher matcher = pattern.matcher(string);
		if (matcher.find())
		{
			String mail = (matcher.group(0));
			if (mail.contains("cert.br"))
				return null;
			else
				return mail;
		} else
			return null;
	}
	
	/**
	 * Reads a log file.
	 *
	 * @param file
	 *          the file
	 * @return the hash map
	 */
	private static HashMap<String, String> readLogFile(File file)
	{
		BufferedReader br = null;
		HashMap<String, String> content = new HashMap<String, String>();
		
		try
		{
			// open file
			br = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
			
			// read it
			String line;
			while ((line = br.readLine()) != null)
			{
				if (checkLine(line))
				{
					String addr = extractIp(line);
					content.put(addr, line);
				}
			}
		} catch (FileNotFoundException e)
		{
			System.err.println("Could not find '" + file.getAbsolutePath() + "'");
		} catch (IOException e)
		{
			System.err.println("Could not read '" + file.getAbsolutePath() + "'");
		} finally
		{
			// close all
			try
			{
				if (br != null)
					br.close();
			} catch (IOException e)
			{
				
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return content;
	}
	
	/**
	 * Read gz file.
	 *
	 * @param file
	 *          the file
	 * @return the content hash map
	 */
	private static HashMap<String, String> readGZFile(File file)
	{
		GZIPInputStream gzip = null;
		BufferedReader br = null;
		
		HashMap<String, String> content = new HashMap<String, String>();
		
		try
		{
			// open compressed file
			gzip = new GZIPInputStream(new FileInputStream(file));
			br = new BufferedReader(new InputStreamReader(gzip));
			
			// read it
			String line;
			while ((line = br.readLine()) != null)
			{
				if (checkLine(line))
				{
					String addr = extractIp(line);
					content.put(addr, line);
				}
			}
		} catch (FileNotFoundException e)
		{
			System.err.println("Could not find '" + file.getAbsolutePath() + "'");
		} catch (IOException e)
		{
			System.err.println("Could not read '" + file.getAbsolutePath() + "'");
		} finally
		{
			// close all
			try
			{
				if (br != null)
					br.close();
				if (gzip != null)
					gzip.close();
			} catch (IOException e)
			{
				
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return content;
	}
	
	/**
	 * Check line.
	 *
	 * @param line
	 *          the line
	 * @return true, if successful
	 */
	private static boolean checkLine(String line)
	{
		
		String regex = ".*Authentication failure for .* from .*";
		
		return line.matches(regex);
	}
	
	/**
	 * Extracts a ip from the input string.
	 *
	 * @param line
	 *          the line
	 * @return the string
	 */
	private static String extractIp(String line)
	{
		String IPADDRESS_PATTERN = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
		
		Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
		Matcher matcher = pattern.matcher(line);
		if (matcher.find())
		{
			return matcher.group();
		} else
		{
			return null;
		}
	}
	
	/**
	 * Print a line.
	 *
	 * @param string
	 *          the string
	 */
	private static void println(String string)
	{
		System.out.println(string);
	}
	
	/**
	 * Parses the arguments.
	 *
	 * @param args
	 *          the arguments
	 */
	private static void parseArguments(String[] args)
	{
		if (args.length > 0)
		{
			logDir = args[0];
		} else
		{
			System.err.println("Directory to log files is mandatory");
		}
		
	}
	
}
