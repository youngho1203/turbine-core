package org.apache.turbine.pipeline;

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

import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.apache.turbine.modules.actions.VelocityActionDoesNothing;
import org.apache.turbine.om.security.TurbineUser;
import org.apache.turbine.om.security.User;
import org.apache.turbine.services.template.TemplateService;
import org.apache.turbine.test.BaseTestCase;
import org.apache.turbine.test.EnhancedMockHttpServletRequest;
import org.apache.turbine.test.EnhancedMockHttpServletResponse;
import org.apache.turbine.test.EnhancedMockHttpSession;
import org.apache.turbine.util.RunData;
import org.apache.turbine.util.TurbineConfig;
import org.apache.turbine.util.uri.URIConstants;

import com.mockobjects.servlet.MockServletConfig;

/**
 * Tests ExecutePageValve.
 *
 * @author <a href="mailto:epugh@opensourceConnections.com">Eric Pugh</a>
 * @author <a href="mailto:peter@courcoux.biz">Peter Courcoux</a>
 * @version $Id$
 */
public class ExecutePageValveTest extends BaseTestCase
{
    private static TurbineConfig tc = null;
    private static TemplateService ts = null;
    private MockServletConfig config = null;
    private EnhancedMockHttpServletRequest request = null;
    private EnhancedMockHttpSession session = null;
    private HttpServletResponse response = null;
    private static ServletConfig sc = null;
    /**
     * Constructor
     */
    public ExecutePageValveTest(String testName) throws Exception
    {
        super(testName);
    }

    protected void setUp() throws Exception
    {
        super.setUp();
        config = new MockServletConfig();
        config.setupNoParameters();
        request = new EnhancedMockHttpServletRequest();
        request.setupServerName("bob");
        request.setupGetProtocol("http");
        request.setupScheme("scheme");
        request.setupPathInfo("damn");
        request.setupGetServletPath("damn2");
        request.setupGetContextPath("wow");
        request.setupGetContentType("html/text");
        request.setupAddHeader("Content-type", "html/text");
        request.setupAddHeader("Accept-Language", "en-US");

        session = new EnhancedMockHttpSession();
        response = new EnhancedMockHttpServletResponse();

        request.setSession(session);

        sc = config;
        tc =
            new TurbineConfig(
                ".",
                "/conf/test/CompleteTurbineResources.properties");
        tc.initialize();
    }

    public void testValve() throws Exception
    {

        
        
        Vector v = new Vector();
        v.add(URIConstants.CGI_TEMPLATE_PARAM);
        request.setupGetParameterNames(v.elements());
        String nulls[] = new String[1];
        nulls[0]="Index.vm";
        request.setupAddParameter(URIConstants.CGI_TEMPLATE_PARAM, nulls);

        RunData runData =
            getRunData(request, response, config);
        
        
        
        runData.setScreenTemplate("ExistPageWithLayout.vm");
        
        
        TurbineUser tu = new TurbineUser();
        tu.setName("username");
        tu.setHasLoggedIn(Boolean.TRUE);
        String actionName = VelocityActionDoesNothing.class.getName();
        actionName = actionName.substring(actionName.lastIndexOf(".")+1);
        runData.setAction(actionName);
        runData.setUser(tu);

        Pipeline pipeline = new TurbinePipeline();

        PipelineData pipelineData = runData;
        ExecutePageValve valve = new ExecutePageValve();
        pipeline.addValve(valve);

        int numberOfCalls = VelocityActionDoesNothing.numberOfCalls;
        pipeline.invoke(pipelineData);
        assertEquals("Assert action was called",numberOfCalls +1,VelocityActionDoesNothing.numberOfCalls);
        User user = runData.getUser();
        assertNotNull(user);
        assertEquals("username", user.getName());
        assertTrue(user.hasLoggedIn());


    }

}
