package org.apache.turbine.modules.pages;

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

import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.velocity.TurbineVelocity;
import org.apache.turbine.services.velocity.VelocityService;

import org.apache.turbine.util.RunData;

import org.apache.velocity.context.Context;

/**
 * Extends TemplatePage to set the template Context.
 *
 * @author <a href="mailto:mbryson@mont.mindspring.com">Dave Bryson</a>
 * @author <a href="mailto:john.mcnally@clearink.com">John D. McNally</a>
 * @author <a href="mailto:hps@intermeta.de">Henning P. Schmiedehausen</a>
 * @author <a href="mailto:peter@courcoux.biz">Peter Courcoux</a>
 * @version $Id$
 */
public class VelocityPage
    extends TemplatePage
{
    /**
     * Stuffs the Context into the RunData so that it is available to
     * the Action module and the Screen module via getContext().
     * @deprecated Use PipelineData version instead.
     * @param data Turbine information.
     * @exception Exception, a generic exception.
     */
    protected void doBuildBeforeAction(RunData data)
        throws Exception
    {
        Context context = TurbineVelocity.getContext(data);
        data.getTemplateInfo()
            .setTemplateContext(VelocityService.CONTEXT, context);
    }

    /**
     * Allows the VelocityService to peform post-request actions.
     * (releases the (non-global) tools in the context for reuse later)
     * @deprecated. Use PipelineData version instead.
     * 
     */
    protected void doPostBuild(RunData data)
        throws Exception
    {
        Context context = TurbineVelocity.getContext(data);
        TurbineVelocity.requestFinished(context);
    }
    
    
    /**
     * Stuffs the Context into the RunData so that it is available to
     * the Action module and the Screen module via getContext().
     * 
     * @param data Turbine information.
     * @exception Exception, a generic exception.
     */
    protected void doBuildBeforeAction(PipelineData pipelineData)
        throws Exception
    {
        RunData data = (RunData) getRunData(pipelineData);
        Context context = TurbineVelocity.getContext(pipelineData);
        data.getTemplateInfo()
            .setTemplateContext(VelocityService.CONTEXT, context);
    }

    /**
     * Allows the VelocityService to peform post-request actions.
     * (releases the (non-global) tools in the context for reuse later)
     */
    protected void doPostBuild(PipelineData pipelineData)
        throws Exception
    {
        Context context = TurbineVelocity.getContext(pipelineData);
        TurbineVelocity.requestFinished(context);
    }

}
