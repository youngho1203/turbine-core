package org.apache.turbine.services.assemblerbroker.util.java;

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

import org.apache.turbine.TurbineConstants;
import org.apache.turbine.modules.Assembler;

/**
 * An action factory that attempts to load a java class from
 * the module packages defined in the TurbineResource.properties.
 *
 * @author <a href="mailto:leon@opticode.co.za">Leon Messerschmidt</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @version $Id$
 */
public class JavaActionFactory
        extends JavaBaseFactory
{
    /**
     * Get an Assembler.
     *
     * @param name name of the requested Assembler
     * @return an Assembler
     */
    public Assembler getAssembler(String name)
    {
        return getAssembler(TurbineConstants.ACTION_PREFIX, name);
    }
}
