package org.apache.turbine.services.db;

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001 The Apache Software Foundation.  All rights
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

import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.configuration.Configuration;
import org.apache.torque.Torque;
import org.apache.torque.adapter.DB;
import org.apache.torque.util.BasePeer;
import org.apache.turbine.services.BaseService;
import org.apache.turbine.services.resources.TurbineResources;


/**
 * Turbine's default implementation of {@link PoolBrokerService}.
 *
 * @author <a href="mailto:frank.kim@clearink.com">Frank Y. Kim</a>
 * @author <a href="mailto:bmclaugh@algx.net">Brett McLaughlin</a>
 * @author <a href="mailto:greg@shwoop.com">Greg Ritter</a>
 * @author <a href="mailto:dlr@finemaltcoding.com">Daniel Rall</a>
 * @author <a href="mailto:magnus@handtolvur.is">Magn�s ��r Torfason</a>
 * @author <a href="mailto:jvanzyl@periapt.com">Jason van Zyl</a>
 * @author <a href="mailto:Rafal.Krzewski@e-point.pl">Rafal Krzewski</a>
 * @version $Id$
 */
public class TurbinePoolBrokerService extends BaseService
    implements PoolBrokerService
{
    /**
     * Name of the default connection pool.
     */
    public static final String DEFAULT = "default";

    /** Default database pool */
    private String defaultPool;

    /**
     * The various connection pools this broker contains.  Keyed by
     * database URL.
     */
    private Map pools;

    /**
     * Initialize the connection pool broker.
     */
    public void init()
    {
        pools = (Map) new HashMap();

        Configuration configuration = getConfiguration();

        // Get the value for the default pool, but if there
        // isn't a value than fall back to the standard
        // "default" value.
        defaultPool = configuration.getString(DEFAULT_POOL, DEFAULT);

        // Create monitor thread
//        Monitor monitor = new Monitor();
        // Indicate that this is a system thread. JVM will quit only when there
        // are no more active user threads. Settings threads spawned internally
        // by Turbine as daemons allows commandline applications using Turbine
        // to terminate in an orderly manner.
//        monitor.setDaemon(true);
//        monitor.start();

        // indicate that the service initialized correctly
        setInit(true);
    }

    /**
     * Return the default pool.
     */
    public String getDefaultDB()
    {
        return Torque.getDefaultDB();
    }

    /**
     * Release the database connections for all pools on service shutdown.
     */
    public synchronized void shutdown()
    {
        Torque.shutdown();
    }

    /**
     * This method returns a DBConnection from the default pool.
     *
     * @return The requested connection.
     * @throws TurbineException Any exceptions caught during processing will be
     *         rethrown wrapped into a TurbineException.
     */
    public Connection getConnection()
        throws Exception
    {
        return Torque.getConnection();
    }

    /**
     * This method returns a DBConnection from the pool with the
     * specified name.  The pool must either have been registered
     * with the {@link #registerPool(String,String,String,String,String)}
     * method, or be specified in the property file using the
     * following syntax:
     *
     * <pre>
     * database.[name].driver
     * database.[name].url
     * database.[name].username
     * database.[name].password
     * </pre>
     *
     * @param name The name of the pool to get a connection from.
     * @return     The requested connection.
     * @throws TurbineException Any exceptions caught during processing will be
     *         rethrown wrapped into a TurbineException.
     */
    public Connection getConnection(String name)
        throws Exception
    {
        return Torque.getConnection(name);
    }

    /**
     * Release a connection back to the database pool.  <code>null</code>
     * references are ignored.
     *
     * @throws TurbineException Any exceptions caught during processing will be
     *         rethrown wrapped into a TurbineException.
     * @exception Exception A generic exception.
     */
    public void releaseConnection(Connection dbconn)
        throws Exception
    {
        BasePeer.closeConnection(dbconn);
    }

    /**
     * Returns the database adapter for the default connection pool.
     *
     * @return The database adapter.
     * @throws TurbineException Any exceptions caught during processing will be
     *         rethrown wrapped into a TurbineException.
     */
    public DB getDB()
        throws Exception
    {
        return getDB(DEFAULT);
    }

    /**
     * Returns database adapter for a specific connection pool.
     *
     * @param name A pool name.
     * @return     The corresponding database adapter.
     * @throws TurbineException Any exceptions caught during processing will be
     *         rethrown wrapped into a TurbineException.
     */
    public DB getDB(String name)
        throws Exception
    {
        return Torque.getDB(getDefaultDB());
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Returns the specified property of the given database, or the empty
     * string if no value is set for the property.
     *
     * @param db   The name of the database whose property to get.
     * @param prop The name of the property to get.
     * @return     The property's value.
     */
    private static final String getDatabaseProperty(String db, String prop)
    {
        return TurbineResources.getString
            ( new StringBuffer("database.")
                .append(db)
                .append('.')
                .append(prop)
                .toString(), "" );
    }

    /**
     * Returns the string for the specified property of the given database.
     *
     * @param db   The name of the database whose property to get.
     * @param prop The name of the property to get.
     * @return     The string of the property.
     */
    private String getProperty(String db, String prop)
    {
        return
            new StringBuffer("database.")
            .append(db)
            .append('.')
            .append(prop)
            .toString();
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * This inner class monitors the <code>PoolBrokerService</code>.
     *
     * This class is capable of logging the number of connections available in
     * the pool periodically. This can prove useful if you application
     * frozes after certain amount of time/requests and you suspect
     * that you have connection leakage problem.
     *
     * Set the <code>database.logInterval</code> property to the number of
     * milliseconds you want to elapse between loging the number of
     * connections.
     */
/*
    protected class Monitor extends Thread
    {
        public void run()
        {
            int logInterval = TurbineResources.getInt("database.logInterval",0);
            StringBuffer buf = new StringBuffer();
            while (logInterval > 0)
            {
                // Loop through all pools and log.
                Iterator poolIter = pools.keySet().iterator();
                while ( poolIter.hasNext() )
                {
                    String poolName = (String) poolIter.next();
                    ConnectionPool pool = (ConnectionPool) pools.get(poolName);
                    buf.setLength(0);
                    buf.append(poolName).append(" (in + out = total): ")
                        .append(pool.getNbrAvailable()).append(" + ")
                        .append(pool.getNbrCheckedOut()).append(" = ")
                        .append(pool.getTotalCount());
                    Log.info("database",buf.toString());
                }

                // Wait for a bit.
                try
                {
                    Thread.sleep(logInterval);
                }
                catch (InterruptedException ignored)
                {
                    // Don't care.
                }
            }
        }
    }
*/
}
