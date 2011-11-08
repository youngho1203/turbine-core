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


import java.io.StringReader;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ecs.ConcreteElement;
import org.apache.fulcrum.xslt.XSLTServiceFacade;
import org.apache.turbine.TurbineConstants;
import org.apache.turbine.modules.Layout;
import org.apache.turbine.modules.Screen;
import org.apache.turbine.modules.ScreenLoader;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.assemblerbroker.TurbineAssemblerBroker;
import org.apache.turbine.services.velocity.TurbineVelocity;
import org.apache.turbine.util.RunData;
import org.apache.turbine.util.template.TemplateNavigation;
import org.apache.velocity.context.Context;

/**
 * This Layout module allows Velocity XML templates to be used as layouts.
 * <br><br>
 * Once the (XML) screen and navigation templates have been inserted into
 * the layout template the result is transformed with a XSL stylesheet.
 * The stylesheet (with the same name than the screen template) is loaded
 * and executed by the XSLT service, so it is important that you correctly
 * set up your XSLT service.  If the named stylsheet does not exist the
 * default.xsl stylesheet is executed.  If default.xsl does not exist
 * the XML is merely echoed.
 * <br><br>
 * Since dynamic content is supposed to be primarily located in
 * screens and navigations there should be relatively few reasons to
 * subclass this Layout.
 *
 * @author <a href="mailto:leon@opticode.co.za">Leon Messerschmidt</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @version $Id$
 */
public class VelocityXslLayout extends Layout
{
    /** Logging */
    private static Log log = LogFactory.getLog(VelocityXslLayout.class);

    /** The prefix for lookup up layout pages */
    private final String prefix = Layout.PREFIX + "/";

    private final ScreenLoader screenLoader;

    /**
     * Default constructor
     */
    public VelocityXslLayout()
    {
        super();

        this.screenLoader = (ScreenLoader)TurbineAssemblerBroker.getLoader(Screen.class);
    }

    /**
     * Build the layout.  Also sets the ContentType and Locale headers
     * of the HttpServletResponse object.
     * @deprecated Use PipelineData version instead.
     * @param data Turbine information.
     * @exception Exception a generic exception.
     */
    @Deprecated
    @Override
    public void doBuild(RunData data)
        throws Exception
    {
        // Get the context needed by Velocity.
        Context context = TurbineVelocity.getContext(data);

        data.getResponse().setContentType("text/html");

        String screenName = data.getScreen();

        log.debug("Loading Screen " + screenName);

        // First, generate the screen and put it in the context so
        // we can grab it the layout template.
        ConcreteElement results =
            screenLoader.eval(data, screenName);

        String returnValue = (results == null) ? "" : results.toString();

        // variable for the screen in the layout template
        context.put(TurbineConstants.SCREEN_PLACEHOLDER, returnValue);

        // variable to reference the navigation screen in the layout template
        context.put(TurbineConstants.NAVIGATION_PLACEHOLDER,
                    new TemplateNavigation(data));

        // Grab the layout template set in the VelocityPage.
        // If null, then use the default layout template
        // (done by the TemplateInfo object)
        String templateName = data.getTemplateInfo().getLayoutTemplate();

        log.debug("Now trying to render layout " + templateName);

        // Now, generate the layout template.
        String temp = TurbineVelocity.handleRequest(context,
                prefix + templateName);

        // Finally we do a transformation and send the result
        // back to the browser
        XSLTServiceFacade.transform(
            data.getTemplateInfo().getScreenTemplate(),
                new StringReader(temp), data.getResponse().getWriter());
    }

    /**
     * Build the layout.  Also sets the ContentType and Locale headers
     * of the HttpServletResponse object.
     *
     * @param data Turbine information.
     * @exception Exception a generic exception.
     */
    @Override
    public void doBuild(PipelineData pipelineData)
        throws Exception
    {
        RunData data = getRunData(pipelineData);
        // Get the context needed by Velocity.
        Context context = TurbineVelocity.getContext(pipelineData);

        data.getResponse().setContentType("text/html");

        String screenName = data.getScreen();

        log.debug("Loading Screen " + screenName);

        // First, generate the screen and put it in the context so
        // we can grab it the layout template.
        ConcreteElement results =
            screenLoader.eval(pipelineData, screenName);

        String returnValue = (results == null) ? "" : results.toString();

        // variable for the screen in the layout template
        context.put(TurbineConstants.SCREEN_PLACEHOLDER, returnValue);

        // variable to reference the navigation screen in the layout template
        context.put(TurbineConstants.NAVIGATION_PLACEHOLDER,
                    new TemplateNavigation(data));

        // Grab the layout template set in the VelocityPage.
        // If null, then use the default layout template
        // (done by the TemplateInfo object)
        String templateName = data.getTemplateInfo().getLayoutTemplate();

        log.debug("Now trying to render layout " + templateName);

        // Now, generate the layout template.
        String temp = TurbineVelocity.handleRequest(context,
                prefix + templateName);

        // Finally we do a transformation and send the result
        // back to the browser
        XSLTServiceFacade.transform(
            data.getTemplateInfo().getScreenTemplate(),
                new StringReader(temp), data.getResponse().getWriter());
    }
}
