package org.apache.turbine.modules;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.turbine.Turbine;
import org.apache.turbine.TurbineConstants;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.assemblerbroker.AssemblerBrokerService;
import org.apache.turbine.services.assemblerbroker.TurbineAssemblerBroker;
import org.apache.turbine.util.RunData;

/**
 * The purpose of this class is to allow one to load and execute
 * Action modules.
 *
 * @author <a href="mailto:mbryson@mont.mindspring.com">Dave Bryson</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @author <a href="mailto:peter@courcoux.biz">Peter Courcoux</a>
 * @version $Id$
 */
public class ActionLoader
    extends GenericLoader
    implements Loader
{
    /** Logging */
    private static Log log = LogFactory.getLog(ActionLoader.class);

    /** The single instance of this class. */
    private static ActionLoader instance = new ActionLoader(getConfiguredCacheSize());

    /** The Assembler Broker Service */
    private static AssemblerBrokerService ab = TurbineAssemblerBroker.getService();

    /**
     * These ctor's are private to force clients to use getInstance()
     * to access this class.
     */
    private ActionLoader()
    {
        super();
    }

    /**
     * These ctor's are private to force clients to use getInstance()
     * to access this class.
     */
    private ActionLoader(int i)
    {
        super(i);
    }

    /**
     * Adds an instance of an object into the hashtable.
     *
     * @param name Name of object.
     * @param action Action to be associated with name.
     */
    private void addInstance(String name, Action action)
    {
        if (cache())
        {
            this.put(name, action);
        }
    }

    /**
     * Attempts to load and execute the external action.
     * @deprecated Use PipelineData version instead.
     * @param data Turbine information.
     * @param name Name of object that will execute the action.
     * @exception Exception a generic exception.
     */
    public void exec(RunData data, String name)
            throws Exception
    {
        // Execute action
        getInstance(name).perform(data);
    }

    /**
     * Attempts to load and execute the external action.
     *
     * @param pipelineData Turbine information.
     * @param name Name of object that will execute the action.
     * @exception Exception a generic exception.
     */
    public void exec(PipelineData pipelineData, String name)
    		throws Exception
    {
        getInstance(name).perform(pipelineData);
    }

    /**
     * Pulls out an instance of the object by name.  Name is just the
     * single name of the object. This is equal to getInstance but
     * returns an Assembler object and is needed to fulfil the Loader
     * interface.
     *
     * @param name Name of object instance.
     * @return An Action with the specified name, or null.
     * @exception Exception a generic exception.
     */
    public Assembler getAssembler(String name)
        throws Exception
    {
        return getInstance(name);
    }

    /**
     * @see org.apache.turbine.modules.Loader#getCacheSize()
     */
    public int getCacheSize()
    {
        return ActionLoader.getConfiguredCacheSize();
    }

    /**
     * Pulls out an instance of the object by name. Name is just the
     * single name of the object.
     *
     * @param name Name of object instance.
     * @return An Action with the specified name, or null.
     * @exception Exception a generic exception.
     */
    public Action getInstance(String name)
            throws Exception
    {
        Action action = null;

        // Check if the action is already in the cache
        if (cache() && this.containsKey(name))
        {
            action = (Action) this.get(name);
            log.debug("Found Action " + name + " in the cache!");
        }
        else
        {
            log.debug("Loading Action " + name + " from the Assembler Broker");

            try
            {
                // Attempt to load the screen
                action = (Action) ab.getAssembler(Action.NAME, name);
            }
            catch (ClassCastException cce)
            {
                // This can alternatively let this exception be thrown
                // So that the ClassCastException is shown in the
                // browser window.  Like this it shows "Screen not Found"
                action = null;
            }

            if (action == null)
            {
                // If we did not find a screen we should try and give
                // the user a reason for that...
                // FIX ME: The AssemblerFactories should each add it's
                // own string here...
                List packages = Turbine.getConfiguration()
                    .getList(TurbineConstants.MODULE_PACKAGES);

                String basePackage = GenericLoader.getBasePackage();

                if (!packages.contains(basePackage))
                {
                    packages.add(basePackage);
                }

                throw new ClassNotFoundException(
                        "\n\n\tRequested Action not found: " + name +
                        "\n\tTurbine looked in the following " +
                        "modules.packages path: \n\t" + packages.toString() + "\n");
            }
            else if (cache())
            {
                // The new instance is added to the cache
                addInstance(name, action);
            }
        }
        return action;
    }

    /**
     * The method through which this class is accessed.
     *
     * @return The single instance of this class.
     */
    public static ActionLoader getInstance()
    {
        return instance;
    }
    
    /**
     * Helper method to get the configured cache size for this module
     * 
     * @return the configure cache size
     */
    private static int getConfiguredCacheSize()
    {
        return Turbine.getConfiguration().getInt(Action.CACHE_SIZE_KEY,
                Action.CACHE_SIZE_DEFAULT);
    }
}
