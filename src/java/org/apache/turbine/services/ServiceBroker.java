package org.apache.turbine.services;

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

import java.util.Properties;
import org.apache.commons.configuration.Configuration;


/**
 * Classes that implement this interface can act as a broker for
 * <code>Service</code> classes.
 *
 * Functionality that <code>ServiceBroker</code> provides in addition
 * to <code>InitableBroker</code> functionality includes:
 *
 * <ul>
 *
 * <li>Maintaining service name to class name mapping, allowing
 * plugable service implementations.</li>
 *
 * <li>Providing <code>Services</code> with <code>Properties</code>
 * based on a system wide configuration mechanism.</li>
 *
 * </ul>
 *
 * @author <a href="mailto:burton@apache.org">Kevin Burton</a>
 * @author <a href="mailto:krzewski@e-point.pl">Rafal Krzewski</a>
 * @author <a href="mailto:dlr@collab.net">Daniel Rall</a>
 * @version $Id$
 */
public interface ServiceBroker
    extends InitableBroker
{
    /**
     * Determines whether a service is registered in the configured
     * <code>TurbineResources.properties</code>.
     *
     * @param serviceName The name of the service whose existance to check.
     * @return Registration predicate for the desired services.
     */
    public boolean isRegistered( String serviceName );

    /**
     * Performs early initialization of specified service.
     *
     * @param name The name of the service.
     * @param data An Object to use for initialization activities.
     * @exception InitializationException, if the service is unknown
     * or can't be initialized.
     */
    public void initService( String name,
                             Object data )
        throws InitializationException;

    /**
     * Performs early initialization of all services.
     *
     * @param data An Object to use for initialization activities.
     */
    public void initServices( Object data );

    /**
     * Shutdowns a Service.
     *
     * This method is used to release resources allocated by a
     * Service, and return it to initial (uninitailized) state.
     *
     * @param name The name of the Service to be uninitialized.
     */
    public void shutdownService( String name );

    /**
     * Shutdowns all Services.
     *
     * This method is used to release resources allocated by
     * Services, and return them to initial (uninitailized) state.
     */
    public void shutdownServices( );


    /**
     * Returns an instance of requested Service.
     *
     * @param name The name of the Service requested.
     * @return An instance of requested Service.
     * @exception InstantiationException, if the service is unknown or
     * can't be initialized.
     */
    public Service getService( String name )
        throws InstantiationException;

    /**
     * Returns the properites of a specific service.  Services use
     * this method to retrieve their properties.
     *
     * @param name The name of the service.
     * @return Properties of requested Service.
     */
     public Properties getProperties( String name );

    /**
     * Returns the configuration of a specific service. Services
     * use this method to retrieve their configuration.
     *
     * @param name The name of the service.
     * @return Configuration of the requested service.
     */
    public Configuration getConfiguration( String name );
}
