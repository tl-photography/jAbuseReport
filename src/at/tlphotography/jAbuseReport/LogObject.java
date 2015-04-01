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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.text.ParseException;

// TODO: Auto-generated Javadoc
/**
 * The Class LogObject.
 */
public class LogObject implements Comparable<LogObject>
{
	
	/** The timestamp. */
	Date		timestamp;
	
	/** The log content. */
	String	logContent;
	
	/**
	 * Instantiates a new log object.
	 *
	 * @param string
	 *          the string
	 */
	public LogObject(String string)
	{
		this.logContent = string;
		this.timestamp = parseDate(string);
	}
	
	/**
	 * Parses the date.
	 *
	 * @param string
	 *          the string
	 * @return the date
	 */
	private Date parseDate(String string)
	{
		Date parsed = new Date();
		try
		{
			SimpleDateFormat format = new SimpleDateFormat("MMM dd HH:mm:ss", Locale.US);
			parsed = format.parse(string.substring(0, 15));
			
		} catch (ParseException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return parsed;
	}
	
	@Override
	public int compareTo(LogObject o)
	{
		return timestamp.compareTo(o.timestamp);
	}
	
}
