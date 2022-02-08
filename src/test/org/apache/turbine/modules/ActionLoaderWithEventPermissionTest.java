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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.fulcrum.security.SecurityService;
import org.apache.fulcrum.security.entity.Group;
import org.apache.fulcrum.security.entity.Role;
import org.apache.fulcrum.security.model.turbine.TurbineModelManager;
import org.apache.fulcrum.security.model.turbine.entity.impl.TurbineUserImpl;
import org.apache.turbine.annotation.AnnotationProcessor;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.modules.actions.VelocitySecureActionEventDoesNothing;
import org.apache.turbine.om.security.DefaultUserImpl;
import org.apache.turbine.om.security.User;
import org.apache.turbine.pipeline.DefaultACLCreationValve;
import org.apache.turbine.pipeline.Pipeline;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.pipeline.TurbinePipeline;
import org.apache.turbine.test.BaseTestCase;
import org.apache.turbine.util.RunData;
import org.apache.turbine.util.TurbineConfig;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * This test case is to verify whether exceptions in Velocity actions are
 * properly bubbled up when action.event.bubbleexception=true. Or, if
 * action.event.bubbleexception=false, then the exceptions should be logged and
 * sunk.
 *
 * @author <a href="mailto:youngho@apache.org">Youngho Cho</a>
 * @author <a href="mailto:epugh@upstate.com">Eric Pugh</a>
 * @author <a href="mailto:peter@courcoux.biz">Peter Courcoux</a>
 */
public class ActionLoaderWithEventPermissionTest extends BaseTestCase
{
    private static TurbineConfig tc = null;
    private ServletConfig config = null;
    private HttpServletRequest request = null;
    private HttpServletResponse response = null;

    @TurbineService
    private static SecurityService security;
    
    /*
     * @see TestCase#setUp()
     */

    @BeforeClass
    public static void init()
    {
        tc = new TurbineConfig(".", "/conf/test/CompleteTurbineResources.properties");
        tc.initialize();
        
        try
        {
            AnnotationProcessor.process(new ActionLoaderWithEventPermissionTest());
        }
        catch(Exception e)
        {
        }
    }

    @Before
    public void setUpBefore() throws Exception
    {
        config = mock(ServletConfig.class);
        request = getMockRequest();
        response = mock(HttpServletResponse.class);
    }

    /*
     * @see TestCase#tearDown()
     */
    @AfterClass
    public static void tearDown() throws Exception
    {
        if (tc != null)
        {
            tc.dispose();
        }
    }

    /**
     * This unit test verifies that if an Action Event doEventSubmit_ is called,
     * a properly annotated method is being called
     *
     * @throws Exception
     *             If something goes wrong with the unit test
     */
    @Test
    public void testActionEventAnnotationWithPermission() throws Exception
    {
        when(request.getParameterValues("eventSubmit_annotatedEvent")).thenReturn(new String[] { "foo" });
        RunData data = getRunData(request, response, config);
        User user = createRoleUser("admin");
        data.setUser(user);
        data.save();

        PipelineData pipelineData = data;
        data.setAction("VelocitySecureActionEventDoesNothing");
        data.getParameters().add("eventSubmit_doWithsetpermission", "foo");

        Pipeline pipeline = new TurbinePipeline();

        DefaultACLCreationValve avalve = new DefaultACLCreationValve();

        pipeline.addValve(avalve);

        //
        pipeline.initialize();
        pipeline.invoke(pipelineData);
                
        int numberOfCalls = VelocitySecureActionEventDoesNothing.numberOfCalls;
        int pipelineDataCalls = VelocitySecureActionEventDoesNothing.pipelineDataCalls;
        int actionEventCalls = VelocitySecureActionEventDoesNothing.isAuthorizedEventCalls;
        try
        {
            ActionLoader.getInstance().exec(pipelineData, data.getAction());
        }
        catch (Exception e)
        {
            fail("Should not have thrown an exception.");
        }
        assertEquals(numberOfCalls + 1, VelocitySecureActionEventDoesNothing.numberOfCalls);
        assertEquals(pipelineDataCalls, VelocitySecureActionEventDoesNothing.pipelineDataCalls);
        assertEquals(actionEventCalls + 1, VelocitySecureActionEventDoesNothing.isAuthorizedEventCalls);
    }

    @Test
    public void testActionEventAnnotationWithoutPermission() throws Exception
    {
        when(request.getParameterValues("eventSubmit_annotatedEvent")).thenReturn(new String[] { "foo" });
        RunData data = getRunData(request, response, config);

        User user = createRoleUser("member");
        data.setUser(user);
        data.save();

        PipelineData pipelineData = data;
        data.setAction("VelocitySecureActionEventDoesNothing");
        data.getParameters().add("eventSubmit_doWithsetpermission", "foo");

        Pipeline pipeline = new TurbinePipeline();

        DefaultACLCreationValve avalve = new DefaultACLCreationValve();

        pipeline.addValve(avalve);

        //
        pipeline.initialize();
        pipeline.invoke(pipelineData);

        data.setAction("VelocitySecureActionEventDoesNothing");
        data.getParameters().add("eventSubmit_doWithsetpermission", "foo");

        int numberOfCalls = VelocitySecureActionEventDoesNothing.numberOfCalls;
        int pipelineDataCalls = VelocitySecureActionEventDoesNothing.pipelineDataCalls;
        int actionEventCalls = VelocitySecureActionEventDoesNothing.isAuthorizedEventCalls;
        try
        {
            ActionLoader.getInstance().exec(pipelineData, data.getAction());
        }
        catch (Exception e)
        {
            fail("Should not have thrown an exception.");
        }
        assertEquals(numberOfCalls + 1, VelocitySecureActionEventDoesNothing.numberOfCalls);
        assertEquals(pipelineDataCalls + 1, VelocitySecureActionEventDoesNothing.pipelineDataCalls);
        assertEquals(actionEventCalls , VelocitySecureActionEventDoesNothing.isAuthorizedEventCalls);
    }


	private User createRoleUser(String roleName) throws Exception
	{

		User user = new DefaultUserImpl(new TurbineUserImpl());
		user.setName(roleName);
		security.getUserManager().addUser(user,"fakepasswrod");

        Group group = null;
        if(security.getGroupManager().checkExists("Global"))
        {
            group = security.getGroupManager().getGroupByName("Global");
        }
        else
        {
            group = security.getGroupManager().getGroupInstance();
            group.setName("Global");
            security.getGroupManager().addGroup(group);
        }
        Role role = security.getRoleManager().getRoleInstance();
        role.setName(roleName);
        security.getRoleManager().addRole(role);

        ((TurbineModelManager)security.getModelManager()).grant(user, group, role);

        return user;
	}
}
