package org.apache.turbine.modules.actions;

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


import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.fulcrum.security.SecurityService;
import org.apache.fulcrum.security.entity.User;
import org.apache.fulcrum.security.model.turbine.TurbineAccessControlList;
import org.apache.turbine.annotation.AnnotationProcessor;
import org.apache.turbine.annotation.TurbineActionEvent;
import org.apache.turbine.annotation.TurbineRequiredRole;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;
/**
 * This action is used to test the secure actionEvent methods.
 *
 * @author <a href="mailto:youngho@apache.org">Youngho Cho</a>
 * @author <a href="mailto:tv@apache.org">Thomas Vandahl</a>
 */
public class VelocitySecureActionEventDoesNothing extends VelocitySecureAction
{
    private static Log log = LogFactory.getLog(VelocitySecureActionEventDoesNothing.class);

    @TurbineService
    private SecurityService security;

    public static int numberOfCalls;
    public static int pipelineDataCalls;
    public static int isAuthorizedCalls;
    public static int isAuthorizedEventCalls;

    /**
     *  Default action is throw an exception.
     *
     * @param  pipelineData           Current RunData information
     * @param  context        Context to populate
     * @throws  Exception  Thrown on error
     */
    @Override
    public void doPerform(PipelineData pipelineData, Context context) throws Exception
    {
        log.debug("Calling doPerform(PipelineData)");
		VelocitySecureActionEventDoesNothing.numberOfCalls++;
        RunData rd = (RunData)pipelineData;
		assertNotNull("PipelineData object was Null.", rd);
		VelocitySecureActionEventDoesNothing.pipelineDataCalls++;
    }

    @TurbineActionEvent("doWithsetpermission")
    @TurbineRequiredRole(value = {"admin"})
    public void doWithsetpermission(PipelineData pipelineData, Context context) throws Exception
    {
        log.debug("Calling doWithsetpermission(PipelineData)");
		VelocitySecureActionEventDoesNothing.numberOfCalls++;
        RunData rd = (RunData)pipelineData;
		assertNotNull("PipelineData object was Null.", rd);
    }

    /**
     * @see org.apache.turbine.modules.actions.VelocitySecureAction#isAuthorized(org.apache.turbine.pipeline.PipelineData)
     */
    @Override
    protected boolean isAuthorized(PipelineData pipelineData) throws Exception
    {
        log.debug("Calling isAuthorized(PipelineData)");
        VelocitySecureActionEventDoesNothing.isAuthorizedCalls++;
        return true;
    }

    /**
     * @see org.apache.turbine.modules.ActionEvent#isAuthorized(org.apache.turbine.pipeline.PipelineData, java.lang.reflect.Method)
     */    
    @Override
	public boolean canInvoke(PipelineData pipelineData, Method method)
		throws Exception
	{
        log.debug("Calling isAuthorized(PipelineData, method)");
        RunData rd = (RunData)pipelineData;
        User user = rd.getUser();

        TurbineAccessControlList<?> acl = security.getUserManager().getACL(user);

        if(AnnotationProcessor.isAuthorized(method, acl))
        {
            VelocitySecureActionEventDoesNothing.isAuthorizedEventCalls++;
            return true;
        }
        log.debug("isAuthorized false");
        return false;
	}    
}
