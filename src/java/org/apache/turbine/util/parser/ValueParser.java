package org.apache.turbine.util.parser;

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" and
 *    "Apache Turbine" must not be used to endorse or promote products
 *    derived from this software without prior written permission. For
 *    written permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    "Apache Turbine", nor may "Apache" appear in their name, without
 *    prior written permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

import java.io.UnsupportedEncodingException;

import java.math.BigDecimal;

import java.text.DateFormat;

import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

import org.apache.torque.om.NumberKey;
import org.apache.torque.om.StringKey;

/**
 * ValueParser is a base interface for classes that need to parse
 * name/value Parameters, for example GET/POST data or Cookies
 * (ParameterParser and CookieParser)
 *
 * <p>NOTE: The name= portion of a name=value pair may be converted
 * to lowercase or uppercase when the object is initialized and when
 * new data is added.  This behaviour is determined by the url.case.folding
 * property in TurbineResources.properties.  Adding a name/value pair may
 * overwrite existing name=value pairs if the names match:
 *
 * @author <a href="mailto:ilkka.priha@simsoft.fi">Ilkka Priha</a>
 * @author <a href="mailto:jon@clearink.com">Jon S. Stevens</a>
 * @author <a href="mailto:sean@informage.net">Sean Legassick</a>
 * @author <a href="mailto:jvanzyl@periapt.com">Jason van Zyl</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @author <a href="mailto:quintonm@bellsouth.net">Quinton McCombs</a>
 * @version $Id$
 */
public interface ValueParser
{
    /**
     * The Key for the Case folding.
     *
     * @deprecated Use ParserUtils.URL_CASE_FOLDING_KEY
     */
    String URL_CASE_FOLDING = ParserUtils.URL_CASE_FOLDING_KEY;

    /**
     * No Case folding.
     *
     * @deprecated Use ParserUtils.URL_CASE_FOLDING_NONE_VALUE
     */
    String URL_CASE_FOLDING_NONE = ParserUtils.URL_CASE_FOLDING_NONE_VALUE;

    /**
     * Fold Keys to lower case.
     *
     * @deprecated Use ParserUtils.URL_CASE_FOLDING_LOWER_VALUE
     */
    String URL_CASE_FOLDING_LOWER = ParserUtils.URL_CASE_FOLDING_LOWER_VALUE;

    /**
     * Fold Keys to upper case.
     *
     * @deprecated Use ParserUtils.URL_CASE_FOLDING_UPPER_VALUE
     */
    String URL_CASE_FOLDING_UPPER = ParserUtils.URL_CASE_FOLDING_UPPER_VALUE;

    /**
     * Clear all name/value pairs out of this object.
     */
    void clear();

    /**
     * Set the character encoding that will be used by this ValueParser.
     */
    void setCharacterEncoding(String s);

    /**
     * Get the character encoding that will be used by this ValueParser.
     */
    String getCharacterEncoding();

    /**
     * Trims the string data and applies the conversion specified in
     * the property given by URL_CASE_FOLDING. It returns a new
     * string so that it does not destroy the value data.
     *
     * @param value A String to be processed.
     * @return A new String converted to lowercase and trimmed.
     */
    String convert(String value);

    /**
     * Add a name/value pair into this object.
     *
     * @param name A String with the name.
     * @param value A double with the value.
     */
    void add(String name, double value);

    /**
     * Add a name/value pair into this object.
     *
     * @param name A String with the name.
     * @param value An int with the value.
     */
    void add(String name, int value);

    /**
     * Add a name/value pair into this object.
     *
     * @param name A String with the name.
     * @param value An Integer with the value.
     */
    void add(String name, Integer value);

    /**
     * Add a name/value pair into this object.
     *
     * @param name A String with the name.
     * @param value A long with the value.
     */
    void add(String name, long value);

    /**
     * Add a name/value pair into this object.
     *
     * @param name A String with the name.
     * @param value A long with the value.
     */
    void add(String name, String value);

    /**
     * Add a String parameter.  If there are any Strings already
     * associated with the name, append to the array.  This is used
     * for handling parameters from mulitipart POST requests.
     *
     * @param name A String with the name.
     * @param value A String with the value.
     */
    void append(String name, String value);

    /**
     * Add an array of Strings for a key. This
     * is simply adding all the elements in the
     * array one by one.
     *
     * @param name A String with the name.
     * @param value A String Array.
     */
    void add(String name, String [] value);

    /**
     * Removes the named parameter from the contained hashtable. Wraps to the
     * contained <code>Hashtable.remove()</code>.
     *
     *
     * @return The value that was mapped to the key (a <code>String[]</code>)
     *         or <code>null</code> if the key was not mapped.
     */
    Object remove(String name);

    /**
     * Determine whether a given key has been inserted.  All keys are
     * stored in lowercase strings, so override method to account for
     * this.
     *
     * @param key An Object with the key to search for.
     * @return True if the object is found.
     */
    boolean containsKey(Object key);

    /**
     * Check for existence of key_day, key_month and key_year
     * parameters (as returned by DateSelector generated HTML).
     *
     * @param key A String with the selector name.
     * @return True if keys are found.
     */
    boolean containsDateSelectorKeys(String key);

    /**
     * Get an enumerator for the parameter keys.
     *
     * @return An <code>enumerator</code> of the keys.
     * @deprecated use {@link #keySet} instead.
     */
    Enumeration keys();

    /**
     * Gets the keys.
     *
     * @return A <code>Set</code> of the keys.
     */
    Set keySet();

    /**
     * Returns all the available parameter names.
     *
     * @return A object array with the keys.
     */
    Object[] getKeys();

    /**
     * Return a boolean for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A boolean.
     */
    boolean getBoolean(String name, boolean defaultValue);

    /**
     * Return a boolean for the given name.  If the name does not
     * exist, return false.
     *
     * @param name A String with the name.
     * @return A boolean.
     */
    boolean getBoolean(String name);

    /**
     * Return a Boolean for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A Boolean.
     * @deprecated use {@link #getBooleanObject} instead
     */
    Boolean getBool(String name, boolean defaultValue);

    /**
     * Return a Boolean for the given name.  If the name does not
     * exist, return false.
     *
     * @param name A String with the name.
     * @return A Boolean.
     * @deprecated use {@link #getBooleanObject} instead
     */
    Boolean getBool(String name);

    /**
     * Returns a Boolean object for the given name.  If the parameter
     * does not exist or can not be parsed as a boolean, null is returned.
     * <p>
     * Valid values for true: true, on, 1, yes<br>
     * Valid values for false: false, off, 0, no<br>
     * <p>
     * The string is compared without reguard to case.
     *
     * @param name A String with the name.
     * @return A Boolean.
     */
    Boolean getBooleanObject(String name);

    /**
     * Returns a Boolean object for the given name.  If the parameter
     * does not exist or can not be parsed as a boolean, the defaultValue
     * is returned.
     * <p>
     * Valid values for true: true, on, 1, yes<br>
     * Valid values for false: false, off, 0, no<br>
     * <p>
     * The string is compared without reguard to case.
     *
     * @param name A String with the name.
     * @return A Boolean.
     */
    Boolean getBooleanObject(String name, Boolean defaultValue);

    /**
     * Return a double for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A double.
     */
    double getDouble(String name, double defaultValue);

    /**
     * Return a double for the given name.  If the name does not
     * exist, return 0.0.
     *
     * @param name A String with the name.
     * @return A double.
     */
    double getDouble(String name);

    /**
     * Return an array of doubles for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return A double[].
     */
    double[] getDoubles(String name);

    /**
     * Return a Double for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A double.
     */
    Double getDoubleObject(String name, Double defaultValue);

    /**
     * Return a Double for the given name.  If the name does not
     * exist, return null.
     *
     * @param name A String with the name.
     * @return A double.
     */
    Double getDoubleObject(String name);

    /**
     * Return an array of doubles for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return A double[].
     */
    Double[] getDoubleObjects(String name);

    /**
     * Return a float for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A float.
     */
    float getFloat(String name, float defaultValue);

    /**
     * Return a float for the given name.  If the name does not
     * exist, return 0.0.
     *
     * @param name A String with the name.
     * @return A float.
     */
    float getFloat(String name);

    /**
     * Return an array of floats for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return A float[].
     */
    float[] getFloats(String name);

    /**
     * Return a Float for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A Float.
     */
    Float getFloatObject(String name, Float defaultValue);

    /**
     * Return a float for the given name.  If the name does not
     * exist, return null.
     *
     * @param name A String with the name.
     * @return A Float.
     */
    Float getFloatObject(String name);

    /**
     * Return an array of floats for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return A float[].
     */
    Float[] getFloatObjects(String name);

    /**
     * Return a BigDecimal for the given name.  If the name does not
     * exist, return 0.0.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A BigDecimal.
     */
    BigDecimal getBigDecimal(String name, BigDecimal defaultValue);

    /**
     * Return a BigDecimal for the given name.  If the name does not
     * exist, return <code>null</code>.
     *
     * @param name A String with the name.
     * @return A BigDecimal.
     */
    BigDecimal getBigDecimal(String name);

    /**
     * Return an array of BigDecimals for the given name.  If the name
     * does not exist, return null.
     *
     * @param name A String with the name.
     * @return A BigDecimal[].
     */
    BigDecimal[] getBigDecimals(String name);

    /**
     * Return an int for the given name.  If the name does not exist,
     * return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return An int.
     */
    int getInt(String name, int defaultValue);

    /**
     * Return an int for the given name.  If the name does not exist,
     * return 0.
     *
     * @param name A String with the name.
     * @return An int.
     */
    int getInt(String name);

    /**
     * Return an Integer for the given name.  If the name does not exist,
     * return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return An Integer.
     */
    Integer getIntObject(String name, Integer defaultValue);

    /**
     * Return an Integer for the given name.  If the name does not exist,
     * return null.
     *
     * @param name A String with the name.
     * @return An Integer.
     */
    Integer getIntObject(String name);

    /**
     * Return an Integer for the given name.  If the name does not
     * exist, return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return An Integer.
     * @deprecated use {@link #getIntObject} instead
     */
    Integer getInteger(String name, int defaultValue);

    /**
     * Return an Integer for the given name.  If the name does not
     * exist, return defaultValue.  You cannot pass in a null here for
     * the default value.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return An Integer.
     * @deprecated use {@link #getIntObject} instead
     */
    Integer getInteger(String name, Integer defaultValue);

    /**
     * Return an Integer for the given name.  If the name does not
     * exist, return <code>null</code>.
     *
     * @param name A String with the name.
     * @return An Integer.
     * @deprecated use {@link #getIntObject} instead
     */
    Integer getInteger(String name);

    /**
     * Return an array of ints for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return An int[].
     */
    int[] getInts(String name);

    /**
     * Return an array of Integers for the given name.  If the name
     * does not exist, return null.
     *
     * @param name A String with the name.
     * @return An Integer[].
     * @deprecated use {@link #getIntObjects} instead
     */
    Integer[] getIntegers(String name);

    /**
     * Return an array of Integers for the given name.  If the name
     * does not exist, return null.
     *
     * @param name A String with the name.
     * @return An Integer[].
     */
    Integer[] getIntObjects(String name);

    /**
     * Return a long for the given name.  If the name does not exist,
     * return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A long.
     */
    long getLong(String name, long defaultValue);

    /**
     * Return a long for the given name.  If the name does not exist,
     * return 0.
     *
     * @param name A String with the name.
     * @return A long.
     */
    long getLong(String name);

    /**
     * Return a Long for the given name.  If the name does not exist,
     * return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A Long.
     */
    Long getLongObject(String name, Long defaultValue);

    /**
     * Return a Long for the given name.  If the name does not exist,
     * return null.
     *
     * @param name A String with the name.
     * @return A Long.
     */
    Long getLongObject(String name);

    /**
     * Return an array of longs for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return A long[].
     */
    long[] getLongs(String name);

    /**
     * Return an array of Longs for the given name.  If the name does
     * not exist, return null.
     *
     * @param name A String with the name.
     * @return A Long[].
     */
    Long[] getLongObjects(String name);

    /**
     * Return a byte for the given name.  If the name does not exist,
     * return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A byte.
     */
    byte getByte(String name, byte defaultValue);

    /**
     * Return a byte for the given name.  If the name does not exist,
     * return 0.
     *
     * @param name A String with the name.
     * @return A byte.
     */
    byte getByte(String name);

    /**
     * Return an array of bytes for the given name.  If the name does
     * not exist, return null. The array is returned according to the
     * HttpRequest's character encoding.
     *
     * @param name A String with the name.
     * @return A byte[].
     * @exception UnsupportedEncodingException
     */
    byte[] getBytes(String name) throws UnsupportedEncodingException;

    /**
     * Return a byte for the given name.  If the name does not exist,
     * return defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A byte.
     */
    Byte getByteObject(String name, Byte defaultValue);

    /**
     * Return a byte for the given name.  If the name does not exist,
     * return 0.
     *
     * @param name A String with the name.
     * @return A byte.
     */
    Byte getByteObject(String name);

    /**
     * Return a String for the given name.  If the name does not
     * exist, return null.
     *
     * @param name A String with the name.
     * @return A String.
     */
    String getString(String name);

    /**
     * Return a String for the given name.  If the name does not
     * exist, return null. It is the same as the getString() method
     * however has been added for simplicity when working with
     * template tools such as Velocity which allow you to do
     * something like this:
     *
     * <code>$data.Parameters.form_variable_name</code>
     *
     * @param name A String with the name.
     * @return A String.
     */
    String get(String name);

    /**
     * Return a String for the given name.  If the name does not
     * exist, return the defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A String.
     */
    String getString(String name, String defaultValue);

    /**
     * Set a parameter to a specific value.
     *
     * This is useful if you want your action to override the values
     * of the parameters for the screen to use.
     * @param name The name of the parameter.
     * @param value The value to set.
     */
    void setString(String name, String value);

    /**
     * Return an array of Strings for the given name.  If the name
     * does not exist, return null.
     *
     * @param name A String with the name.
     * @return A String[].
     */
    String[] getStrings(String name);

    /**
     * Return an array of Strings for the given name.  If the name
     * does not exist, return the defaultValue.
     *
     * @param name A String with the name.
     * @param defaultValue The default value.
     * @return A String[].
     */
    String[] getStrings(String name, String[] defaultValue);

    /**
     * Set a parameter to a specific value.
     *
     * This is useful if you want your action to override the values
     * of the parameters for the screen to use.
     * @param name The name of the parameter.
     * @param values The value to set.
     */
    void setStrings(String name, String[] values);

    /**
     * Return an Object for the given name.  If the name does not
     * exist, return null.
     *
     * @param name A String with the name.
     * @return An Object.
     */
    Object getObject(String name);

    /**
     * Return an array of Objects for the given name.  If the name
     * does not exist, return null.
     *
     * @param name A String with the name.
     * @return An Object[].
     */
    Object[] getObjects(String name);

    /**
     * Returns a java.util.Date object.  String is parsed by supplied
     * DateFormat.  If the name does not exist, return the
     * defaultValue.
     *
     * @param name A String with the name.
     * @param df A DateFormat.
     * @param defaultValue The default value.
     * @return A Date.
     */
    Date getDate(String name, DateFormat df, Date defaultValue);

    /**
     * Returns a java.util.Date object.  If there are DateSelector
     * style parameters then these are used.  If not and there is a
     * parameter 'name' then this is parsed by DateFormat.  If the
     * name does not exist, return null.
     *
     * @param name A String with the name.
     * @return A Date.
     */
    Date getDate(String name);

    /**
     * Returns a java.util.Date object.  String is parsed by supplied
     * DateFormat.  If the name does not exist, return null.
     *
     * @param name A String with the name.
     * @param df A DateFormat.
     * @return A Date.
     */
    Date getDate(String name, DateFormat df);

    /**
     * Return an NumberKey for the given name.  If the name does not
     * exist, return null.
     *
     * @param name A String with the name.
     * @return An NumberKey.
     * @deprecated no replacement
     */
    NumberKey getNumberKey(String name);

    /**
     * Return an NumberKey for the given name.  If the name does not
     * exist, return null.
     *
     * @param name A String with the name.
     * @return An StringKey.
     * @deprecated no replacement
     */
    StringKey getStringKey(String name);

    /**
     * Uses bean introspection to set writable properties of bean from
     * the parameters, where a (case-insensitive) name match between
     * the bean property and the parameter is looked for.
     *
     * @param bean An Object.
     * @exception Exception a generic exception.
     */
    void setProperties(Object bean) throws Exception;

    /**
     * Simple method that attempts to get a toString() representation
     * of this object.  It doesn't do well with String[]'s though.
     *
     * @return A String.
     */
    String toString();
}