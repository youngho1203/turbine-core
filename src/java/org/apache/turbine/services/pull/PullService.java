package org.apache.turbine.services.pull;

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

import org.apache.turbine.services.Service;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;

/**
 * The Pull Service manages the creation of application
 * tools that are available to all templates in a
 * Turbine application. By using the Pull Service you
 * can avoid having to make Screens to populate a
 * context for use in a particular template. The Pull
 * Service creates a set of tools, as specified in
 * the TR.props file.
 *
 * These tools can have global scope, request scope,
 * authorized or session scope (i.e. stored in user temp hashmap)
 * or persistent scope (i.e. stored in user perm hashmap)
 *
 * The standard way of referencing these global
 * tools is through the toolbox handle. This handle
 * is typically $toolbox, but can be specified in the
 * TR.props file.
 *
 * So, for example, if you had a UI Manager tool
 * which created a set of UI attributes from a
 * properties file, and one of the properties
 * was 'bgcolor', then you could access this
 * UI attribute with $ui.bgcolor. The identifier
 * that is given to the tool, in this case 'ui', can
 * be specified as well.
 *
 * @author <a href="mailto:jvanzyl@periapt.com">Jason van Zyl</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @version $Id$
 */
public interface PullService
        extends Service
{
    /** The key under which this service is stored in TurbineServices. */
    String SERVICE_NAME = "PullService";

    /** Property Key for the global tools */
    String GLOBAL_TOOL = "tool.global";

    /** Property Key for the request tools */
    String REQUEST_TOOL = "tool.request";

    /** Property Key for the session tools */
    String SESSION_TOOL = "tool.session";

    /** Property Key for the authorized tools */
    String AUTHORIZED_TOOL = "tool.authorized";

    /** Property Key for the persistent tools */
    String PERSISTENT_TOOL = "tool.persistent";

    /** Property tag for application tool resources directory */
    String TOOL_RESOURCES_DIR_KEY = "tools.resources.dir";

    /**
     * Default value for the application tool resources. This is relative
     * to the webapp root
     */
    String TOOL_RESOURCES_DIR_DEFAULT = "resources";

    /**
     * Property tag for per request tool refreshing (for obvious reasons
     * has no effect for per-request tools)
     */
    String TOOLS_PER_REQUEST_REFRESH_KEY = "tools.per.request.refresh";

    /** Default value for per request tool refreshing */
    boolean TOOLS_PER_REQUEST_REFRESH_DEFAULT = false;

    /** prefix for key used in the session to store session scope pull tools */
    String SESSION_TOOLS_ATTRIBUTE_PREFIX = "turbine.sessiontools.";

    /**
     * Get the context containing global tools that will be
     * use as part of the Turbine Pull Model.
     *
     * @return A Context object which contains the
     *         Global Tool instances.
     */
    Context getGlobalContext();

    /**
     * Populate the given context with all request, session, authorized
     * and persistent scope tools (it is assumed that the context
     * already wraps the global context, and thus already contains
     * the global tools).
     *
     * @param context a Velocity Context to populate
     * @param data a RunData object for request specific data
     */
    void populateContext(Context context, RunData data);

    /**
     * Return the absolute path of the resources directory
     * used by application tools.
     *
     * @return A directory path in the file system or null.
     */
    String getAbsolutePathToResourcesDirectory();

    /**
     * Return the resources directory. This is relative
     * to the webapp context.
     *
     * @return A directory path to the resources directory relative to the webapp root or null.
     */
    String getResourcesDirectory();

    /**
     * Refresh the global tools .
     * @deprecated No longer needed as Pull and Velocity Service are now more separate.
     */
    void refreshGlobalTools();

    /**
     * Shoud we refresh the tools
     * on each request. For development purposes.
     *
     * @return true if we should refresh the tools on every request.
     * @deprecated No longer needed as Pull and Velocity Service are now more separate.
     */
    boolean refreshToolsPerRequest();

    /**
     * Release tool instances from the given context to the
     * object pool
     *
     * @param context a Velocity Context to release tools from
     */
    void releaseTools(Context context);
}
