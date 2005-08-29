package org.apache.turbine.services.assemblerbroker;

/*
 * Copyright 2001-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.turbine.modules.Assembler;
import org.apache.turbine.services.InitializationException;
import org.apache.turbine.services.TurbineBaseService;
import org.apache.turbine.services.assemblerbroker.util.AssemblerFactory;
import org.apache.turbine.util.TurbineException;

/**
 * TurbineAssemblerBrokerService allows assemblers (like screens,
 * actions and layouts) to be loaded from one or more AssemblerFactory
 * classes.  AssemblerFactory classes are registered with this broker
 * by adding them to the TurbineResources.properties file.
 *
 * @author <a href="mailto:leon@opticode.co.za">Leon Messerschmidt</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @version $Id$
 */
public class TurbineAssemblerBrokerService
        extends TurbineBaseService
        implements AssemblerBrokerService
{
    /** Logging */
    private static Log log
            = LogFactory.getLog(TurbineAssemblerBrokerService.class);

    /** A structure that holds the registered AssemblerFactories */
    private Map factories = null;

    /**
     * Get a list of AssemblerFactories of a certain type
     *
     * @param type type of Assembler
     * @return list of AssemblerFactories
     */
    private List getFactoryGroup(String type)
    {
        if (!factories.containsKey(type))
        {
            factories.put(type, new Vector());
        }
        return (List) factories.get(type);
    }

    /**
     * Utiltiy method to register all factories for a given type.
     *
     * @param type type of Assembler
     * @throws TurbineException
     */
    private void registerFactories(String type)
        throws TurbineException
    {
        List names = getConfiguration().getList(type);

        log.info("Registering " + names.size() + " " + type + " factories.");

        for (Iterator it = names.iterator(); it.hasNext(); )
        {
            String factory = (String) it.next();
            try
            {
                Object o = Class.forName(factory).newInstance();
                registerFactory(type, (AssemblerFactory) o);
            }
            // these must be passed to the VM
            catch (ThreadDeath e)
            {
                throw e;
            }
            catch (OutOfMemoryError e)
            {
                throw e;
            }
            // when using Class.forName(), NoClassDefFoundErrors are likely
            // to happen (missing jar files)
            catch (Throwable t)
            {
                throw new TurbineException("Failed registering " + type
                        + " factory: " + factory, t);
            }
        }
    }

    /**
     * Initializes the AssemblerBroker and loads the AssemblerFactory
     * classes registered in TurbineResources.Properties.
     *
     * @throws InitializationException
     */
    public void init()
        throws InitializationException
    {
        factories = new HashMap();
        try
        {
            registerFactories(AssemblerBrokerService.ACTION_TYPE);
            registerFactories(AssemblerBrokerService.SCREEN_TYPE);
            registerFactories(AssemblerBrokerService.NAVIGATION_TYPE);
            registerFactories(AssemblerBrokerService.LAYOUT_TYPE);
            registerFactories(AssemblerBrokerService.PAGE_TYPE);
            registerFactories(AssemblerBrokerService.SCHEDULEDJOB_TYPE);
        }
        catch (TurbineException e)
        {
            throw new InitializationException(
                    "AssemblerBrokerService failed to initialize", e);
        }
        setInit(true);
    }

    /**
     * Register a new AssemblerFactory under a certain type
     *
     * @param type type of Assembler
     * @param factory factory to register
     */
    public void registerFactory(String type, AssemblerFactory factory)
    {
        getFactoryGroup(type).add(factory);
    }

    /**
     * Attempt to retrieve an Assembler of a given type with
     * a name.  Cycle through all the registered AssemblerFactory
     * classes of type and return the first non-null assembly
     * found.  If an assembly was not found return null.
     *
     * @param type type of Assembler
     * @param name name of the requested Assembler
     * @return an Assembler or null
     * @throws TurbineException
     */
    public Assembler getAssembler(String type, String name)
        throws TurbineException
    {
        List facs = getFactoryGroup(type);

        Assembler assembler = null;
        for (Iterator it = facs.iterator(); (assembler == null) && it.hasNext();)
        {
            AssemblerFactory fac = (AssemblerFactory) it.next();
            try
            {
                assembler = fac.getAssembler(name);
            }
            catch (Exception e)
            {
                throw new TurbineException("Failed to load an assembler for "
                                           + name + " from the "
                                           + type + " factory "
                                           + fac.getClass().getName(), e);
            }
        }
        return assembler;
    }
}
