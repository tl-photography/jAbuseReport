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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.net.whois.WhoisClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// TODO: Auto-generated Javadoc
/**
 * The Main Class.
 */
public class Reporter {

	private static final Logger logger = LogManager.getLogger("jAbuseReport");

	/**
	 * the command line options
	 */
	private static CommandLine cmd;

	/**
	 * The main method.
	 *
	 * @param args
	 *            the arguments
	 */
	public static void main(String[] args) {
		logger.info("starting");
		CharSequence logNames = "auth.log";
		HashMap<String, String> content = new HashMap<String, String>();

		logger.debug("parsing command lines");
		cmd = parseArguments(args);

		// get the files in the dir
		File directory = new File(cmd.getOptionValue('d'));
		File[] filesInDirectory = directory.listFiles();
		logger.debug("searching directory (" + directory.getAbsolutePath() + ")");

		for (File file : filesInDirectory) // iterate over the file
		{
			// if the file is not a dir and the name contains the logName string
			if (!file.isDirectory() && file.getName().contains(logNames)) {
				logger.debug("found file '" + file.getAbsolutePath() + "', reading...");
				content.putAll(readLogFile(file));
			}
		}

		logger.info("done reading log files");

		// save the mails to the log lines
		HashMap<String, ArrayList<LogObject>> finalContent = new HashMap<>();

		Iterator<Entry<String, String>> it = content.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, String> pair = it.next();
			String mail = whoIsLookUp(pair.getKey());
			logger.info("found mail (" + mail + ") for entry " + pair.getKey());
			if (finalContent.containsKey(mail)) {
				finalContent.get(mail).add(new LogObject(pair.getValue()));
			} else {
				ArrayList<LogObject> temp = new ArrayList<LogObject>();
				temp.add(new LogObject(pair.getValue()));
				finalContent.put(mail, temp);
			}

			it.remove();
		}

		logger.info("sorting the entries");
		// sort them
		Iterator<Entry<String, ArrayList<LogObject>>> it2 = finalContent.entrySet().iterator();
		while (it2.hasNext()) {
			Entry<String, ArrayList<LogObject>> pair = it2.next();
			Collections.sort(pair.getValue());
			println(pair.getKey() + " =");
			for (LogObject obj : pair.getValue()) {
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
	 *            the ip
	 * @return the string
	 */
	private static String whoIsLookUp(String ip) {
		String[] serverList = { "whois.ripe.net", "whois.lacnic.net", "whois.registro.br", "whois.nic.ac",
				"whois.aeda.net.ae", "whois.aero", "whois.nic.af", "whois.nic.ag", "whois.ripe.net", "whois.amnic.net",
				"whois.nic.as", "whois.nic.asia", "whois.nic.at", "whois.aunic.net", "whois.ax", "whois.dns.be",
				"whois.register.bg", "whois.nic.bi", "whois.neulevel.biz", "www.nic.bj", "whois.nic.br",
				"whois.centralnic.com", "whois.netnames.net", "whois.cctld.by", "whois.belizenic.bz", "whois.cira.ca",
				"whois.cat", "whois.nic.cc", "whois.nic.cd", "whois.nic.ch", "whois.nic.ck", "whois.nic.cl",
				"whois.cnnic.net.cn", "whois.nic.co", "whois.co.nl", "whois.verisign-grs.com", "whois.nic.coop",
				"whois.nic.cx", "whois.nic.cz", "whois.denic.de", "whois.dk-hostmaster.dk", "whois.nic.dz",
				"whois.educause.net", "whois.tld.ee", "whois.nic.es", "whois.eu", "whois.ficora.fi", "whois.nic.fo",
				"whois.nic.fr", "whois.nic.gl", "whois.nic.gov", "whois.nic.gs", "whois.hknic.net.hk",
				"whois.registry.hm", "whois2.afilias-grs.net", "whois.dns.hr", "whois.nic.hu", "whois.pandi.or.id",
				"whois.domainregistry.ie", "whois.isoc.org.il", "whois.inregistry.net", "whois.afilias.info",
				"whois.isi.edu", "whois.nic.io", "vrx.net", "whois.nic.ir", "whois.isnic.is", "whois.nic.it",
				"whois.je", "jobswhois.verisign-grs.com", "whois.jprs.jp", "whois.kenic.or.ke", "whois.domain.kg",
				"whois.nic.or.kr", "whois.nic.li", "whois.domreg.lt", "whois.restena.lu", "whois.nic.lv",
				"whois.lydomains.com", "whois.iam.net.ma", "whois.nic.md", "whois.nic.me", "whois.nic.mil",
				"whois.dotmobiregistry.net", "whois.nic.ms", "whois.nic.mu", "whois.nic.mx", "whois.mynic.net.my",
				"whois.nic.name", "whois.nic.net.ng", "whois.domain-registry.nl", "whois.norid.no", "whois.nic.nu",
				"whois.srs.net.nz", "whois.pir.org", "whois.dns.pl", "whois.nic.pr", "whois.registrypro.pro",
				"whois.dns.pt", "whois.nic.pw", "whois.rotld.ro", "whois.tcinet.ru", "saudinic.net.sa",
				"whois.nic.net.sb", "whois.nic-se.se", "whois.nic.net.sg", "whois.nic.sh", "whois.arnes.si",
				"whois.sk-nic.sk", "whois.nic.sm", "whois.nic.st", "whois.nic.so", "whois.adamsnames.tc",
				"whois.nic.tel", "whois.nic.tf", "whois.thnic.net", "whois.nic.tj", "whois.nic.tk", "whois.domains.tl",
				"whois.nic.tm", "whois.ati.tn", "whois.tonic.to", "whois.nic.tr", "whois.nic.travel",
				"whois.twnic.net.tw", "whois.nic.tv", "whois.tznic.or.tz", "whois.ua", "whois.nic.uk", "whois.ja.net",
				"whois.nic.us", "nic.uy", "whois.cctld.uz", "whois.nic.ve", "whois.website.ws", "whois.nic.xxx" };

		WhoisClient whois = new WhoisClient();

		for (String server : serverList) {

			logger.debug("try server '" + server + "'");
			try {
				whois.connect(server);
				String whoisData = whois.query(ip);
				StringBuilder result = new StringBuilder("");

				result.append(whoisData);

				String mail = extractEMail(result.toString());
				if (mail != null)
					return mail;
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				logger.error(e);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				logger.error(e);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				logger.error(e);
			} finally {
				try {
					if (whois.isConnected())
						whois.disconnect();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					logger.error(e);
				}
			}
		}
		return "not found";
	}

	/**
	 * Extracts a eMail from string.
	 *
	 * @param string
	 *            the string
	 * @return the string
	 */
	private static String extractEMail(String string) {
		String EMAILADDRESS_PATTERN = "[a-zA-Z0-9_.-]*abuse[a-zA-Z0-9_.-]*@[a-zA-Z0-9_.-]*\\.[a-zA-Z0-9_.-]{2,4}";

		Pattern pattern = Pattern.compile(EMAILADDRESS_PATTERN);

		Matcher matcher = pattern.matcher(string);
		if (matcher.find()) {
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
	 *            the file
	 * @return the hash map
	 */
	private static HashMap<String, String> readLogFile(File file) {
		BufferedReader br = null;
		HashMap<String, String> content = new HashMap<String, String>();

		try {
			// open file

			// is it zipped?
			if (file.getName().endsWith(".gz")) {
				// open compressed file
				GZIPInputStream gzip = new GZIPInputStream(new FileInputStream(file));
				br = new BufferedReader(new InputStreamReader(gzip));
			} else {
				br = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
			}

			// read it
			String line;
			while ((line = br.readLine()) != null) {
				if (checkLine(line)) {
					String addr = extractIp(line);
					content.put(addr, line);
				}
			}
		} catch (FileNotFoundException e) {
			System.err.println("Could not find '" + file.getAbsolutePath() + "'");
			logger.error(e);
		} catch (IOException e) {
			System.err.println("Could not read '" + file.getAbsolutePath() + "'");
			logger.error(e);
		} finally {
			// close all
			try {
				if (br != null)
					br.close();
			} catch (IOException e) {

				// TODO Auto-generated catch block
				logger.error(e);
			}
		}
		return content;
	}

	/**
	 * Check line.
	 *
	 * @param line
	 *            the line
	 * @return true, if successful
	 */
	private static boolean checkLine(String line) {

		String regex = ".*Authentication failure for .* from .*";

		return line.matches(regex);
	}

	/**
	 * Extracts a ip from the input string.
	 *
	 * @param line
	 *            the line
	 * @return the string
	 */
	private static String extractIp(String line) {
		String IPADDRESS_PATTERN = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

		Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
		Matcher matcher = pattern.matcher(line);
		if (matcher.find()) {
			return matcher.group();
		} else {
			return null;
		}
	}

	/**
	 * Print a line.
	 *
	 * @param string
	 *            the string
	 */
	private static void println(String string) {
		System.out.println(string);
	}

	/**
	 * Parses the arguments.
	 *
	 * @param args
	 *            the arguments
	 * @return
	 */
	private static CommandLine parseArguments(String[] args) {

		// create Options object
		Options options = new Options();

		// add option
		Option path = new Option("d", "dir", true, "path to log files");
		Option proxy = new Option("p", "proxy", true, "use a proxy server for whois lookup (xxx.xxx.xxx.xxx:yyyy)");

		options.addOption(path);
		options.addOption(proxy);

		CommandLineParser parser = new DefaultParser();
		CommandLine cmd = null;
		try {
			cmd = parser.parse(options, args);
		} catch (ParseException e) {
			System.err.println("Could not parse command line arguments");
			logger.error(e);
		}

		// if the directory is not set, exit
		if (!cmd.hasOption('d')) {
			System.err.println("log file directory (-d) not set in arguments");
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("jAbuseReport", options);
			System.exit(0);
		}

		return cmd;

	}

}
