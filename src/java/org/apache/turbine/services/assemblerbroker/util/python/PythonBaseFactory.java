package org.apache.turbine.services.assemblerbroker.util.python;


/*
 * Copyright 2001-2004 The Apache Software Foundation.
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


import java.io.File;

import org.apache.commons.configuration.Configuration;

import org.apache.commons.lang.StringUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.turbine.modules.Assembler;
import org.apache.turbine.services.assemblerbroker.TurbineAssemblerBroker;
import org.apache.turbine.services.assemblerbroker.util.AssemblerFactory;

import org.python.core.Py;
import org.python.util.PythonInterpreter;

/**
 * A factory that attempts to load a python class in the
 * JPython interpreter and execute it as a Turbine screen.
 * The JPython script should inherit from Turbine Screen or one
 * of its subclasses.
 *
 * @author <a href="mailto:leon@opticode.co.za">Leon Messerschmidt</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @version $Id$
 */
public abstract class PythonBaseFactory
        implements AssemblerFactory
{
    /** Key for the python path */
    public static final String PYTHON_PATH = "python.path";

    /** Global config file. This is executed before every screen */
    public static final String PYTHON_CONFIG_FILE = "conf.py";

    /** Logging */
    private static Log log = LogFactory.getLog(PythonBaseFactory.class);

    /** Our configuration */
    private Configuration conf =
        TurbineAssemblerBroker.getService().getConfiguration();

    /**
     * Get an Assembler.
     *
     * @param subDirectory subdirectory within python.path
     * @param name name of the requested Assembler
     * @return an Assembler
     * @throws Exception generic exception
     */
    public Assembler getAssembler(String subDirectory, String name)
            throws Exception
    {
        String path = conf.getString(PYTHON_PATH);

        if (StringUtils.isEmpty(path))
        {
            throw new Exception(
                "Python path not found - check your Properties");
        }
            
        log.debug("Screen name for JPython: " + name);

        Assembler assembler = null;

        String confName = path + "/" + PYTHON_CONFIG_FILE;

        // The filename of the Python script
        StringBuffer fName = new StringBuffer();

        fName.append(path);
        fName.append("/");
        fName.append(subDirectory);
        fName.append("/");
        fName.append(name.toLowerCase());
        fName.append(".py");

        File f = new File(fName.toString());

        if (f.exists())
        {
            try
            {
                // We try to open the Py Interpreter
                PythonInterpreter interp = new PythonInterpreter();

                // Make sure the Py Interpreter use the right classloader
                // This is necessary for servlet engines generally has
                // their own classloader implementations and servlets aren't
                // loaded in the system classloader.  The python script will
                // load java package
                // org.apache.turbine.services.assemblerbroker.util.python;
                // the new classes to it as well.
                Py.getSystemState().setClassLoader(
                        this.getClass().getClassLoader());

                // We import the Python SYS module. Now we don't need to do this
                // explicitely in the script.  We always use the sys module to
                // do stuff like loading java package
                // org.apache.turbine.services.assemblerbroker.util.python;
                interp.exec("import sys");

                // Now we try to load the script file
                interp.execfile(confName);
                interp.execfile(fName.toString());

                try
                {
                    // We create an instance of the screen class from the
                    // python script
                    interp.exec("scr = " + name + "()");
                }
                catch (Throwable e)
                {
                    throw new Exception(
                        "\nCannot create an instance of the python class.\n"
                        + "You probably gave your class the wrong name.\n"
                        + "Your class should have the same name as your "
                        + "filename.\nFilenames should be all lowercase and "
                        + "classnames should start with a capital.\n"
                        + "Expected class name: " + name + "\n");
                }

                // Here we convert the python sceen instance to a java instance.
                assembler = (Assembler) interp.get("scr", Assembler.class);
            }
            catch (Exception e)
            {
                // We log the error here because this code is not widely tested
                // yet. After we tested the code on a range of platforms this
                // won't be usefull anymore.
                log.error("PYTHON SCRIPT SCREEN LOADER ERROR:", e);
                throw e;
            }
        }
        return assembler;
    }
}
