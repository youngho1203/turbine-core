package org.apache.turbine.modules.layouts;

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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.turbine.TurbineConstants;
import org.apache.turbine.modules.Layout;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.velocity.TurbineVelocity;
import org.apache.turbine.util.RunData;
import org.apache.turbine.util.template.TemplateNavigation;
import org.apache.turbine.util.template.TemplateScreen;
import org.apache.velocity.context.Context;

/**
 * This Layout module is Turbine 2.3.3 VelocityDirectLayout (same package) 
 * with methods added for {@link PipelineData}. It is used in Jetspeed-1 portal.
 *
 * @author <a href="mailto:raphael@apache.org">Raphaël Luta</a>
 * @author <a href="mailto:john.mcnally@clearink.com">John D. McNally</a>
 * @author <a href="mailto:mbryson@mont.mindspring.com">Dave Bryson</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @version $Id$
 */
public class VelocityCachedLayout
    extends Layout
{
    /** Logging */
    private static Log log = LogFactory.getLog(VelocityCachedLayout.class);

    /** The prefix for lookup up layout pages */
    private String prefix = getPrefix() + "/";

    /**
     * Method called by LayoutLoader.
     *
     * @param data Turbine information.
     * @exception Exception a generic exception.
     */
    public void doBuild(RunData data)
        throws Exception
    {
        // Get the context needed by Velocity.
        Context context = TurbineVelocity.getContext(data);

        // variable for the screen in the layout template
        context.put(TurbineConstants.SCREEN_PLACEHOLDER,
                    new TemplateScreen(data));

        // variable to reference the navigation screen in the layout template
        context.put(TurbineConstants.NAVIGATION_PLACEHOLDER,
                    new TemplateNavigation(data));

        // Grab the layout template set in the VelocityPage.
        // If null, then use the default layout template
        // (done by the TemplateInfo object)
        String templateName = data.getTemplateInfo().getLayoutTemplate();

        // Set the locale and content type
        data.getResponse().setLocale(data.getLocale());
        data.getResponse().setContentType(data.getContentType());

        log.debug("Now trying to render layout " + templateName);

        // Finally, generate the layout template and send it to the browser
        TurbineVelocity.handleRequest(context,
                prefix + templateName, data.getOut());
    }
    
    /**
     * Method called by LayoutLoader.
     *
     *
     * @param data PipelineData
     * @throws Exception generic exception
     */
    @Override
    public void doBuild(PipelineData pipelineData)
        throws Exception
    {
        RunData data = getRunData(pipelineData);
        // Get the context needed by Velocity.
        Context context = TurbineVelocity.getContext(pipelineData);

        // variable for the screen in the layout template
        context.put(TurbineConstants.SCREEN_PLACEHOLDER,
                    new TemplateScreen(data));

        // variable to reference the navigation screen in the layout template
        context.put(TurbineConstants.NAVIGATION_PLACEHOLDER,
                    new TemplateNavigation(data));

        // Grab the layout template set in the VelocityPage.
        // If null, then use the default layout template
        // (done by the TemplateInfo object)
        String templateName = data.getTemplateInfo().getLayoutTemplate();

        // Set the locale and content type
        data.getResponse().setLocale(data.getLocale());
        data.getResponse().setContentType(data.getContentType());

        log.debug("Now trying to render layout " + templateName);

        // Finally, generate the layout template and send it to the browser
        TurbineVelocity.handleRequest(context,
                prefix + templateName, data.getOut());
    }
}
