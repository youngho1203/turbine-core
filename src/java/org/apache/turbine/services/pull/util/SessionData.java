package org.apache.turbine.services.pull.util;

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

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.turbine.services.pull.ApplicationTool;

/**
 * Pull tool designed to be used in the session scope for storage of
 * temporary data.  This tool should eliminate the need for the
 * {@link org.apache.turbine.om.security.User#setTemp} and
 * {@link org.apache.turbine.om.security.User#getTemp} methods.
 *
 * @author <a href="mailto:quintonm@bellsouth.net">Quinton McCombs</a>
 * @version $Id$
 */
public class SessionData implements ApplicationTool
{
    /** Storage of user defined data */
    private Map dataStorage;

    /**
     * Initialize the application tool.
     *
     * @param data initialization data
     */
    public void init(Object data)
    {
        dataStorage = new HashMap();
    }

    /**
     * Refresh the application tool.
     */
    public void refresh()
    {
        // do nothing
    }

    /**
     * Gets the data stored under the key.  Null will be returned if the
     * key does not exist or if null was stored under the key.
     * <p>
     * To check for a key with a null value use {@link #containsKey}.
     *
     * @param key key under which the data is stored.
     * @return <code>Object</code> stored under the key.
     */
    public Object get(String key)
    {
        return dataStorage.get(key);
    }

    /**
     * Determines is a given key is stored.
     *
     * @param key  the key to check for
     * @return true if the key was found
     */
    public boolean containsKey(String key)
    {
        return dataStorage.containsKey(key);
    }

    /**
     * Stores the data.  If the key already exists, the value will be
     * overwritten.
     *
     * @param key   key under which the data will be stored.
     * @param value data to store under the key.  Null values are allowed.
     */
    public void put(String key, Object value)
    {
        dataStorage.put(key, value);
    }

    /**
     * Clears all data
     */
    public void clear()
    {
        dataStorage.clear();
    }

    /**
     * Gets a iterator for the keys.
     *
     * @return <code>Iterator</code> for the keys
     */
    public Iterator iterator()
    {
        return dataStorage.keySet().iterator();
    }
}