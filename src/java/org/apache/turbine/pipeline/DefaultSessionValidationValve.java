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

import java.io.IOException;

import org.apache.turbine.Turbine;
import org.apache.turbine.TurbineConstants;
import org.apache.turbine.modules.ActionLoader;
import org.apache.turbine.modules.actions.sessionvalidator.SessionValidator;
import org.apache.turbine.util.RunData;
import org.apache.turbine.util.TurbineException;

/**
 * Implements the action portion of the "Turbine classic" processing
 * pipeline (from the Turbine 2.x series).
 *
 * @author <a href="mailto:jvanzyl@apache.org">Jason van Zyl</a>\
 * @author <a href="mailto:peter@courcoux.biz">Peter Courcoux</a>
 * @version $Id$
 */
public class DefaultSessionValidationValve
    extends AbstractValve
    implements TurbineConstants
{
    protected SessionValidator sessionValidator = null;

    
    public DefaultSessionValidationValve()
        throws Exception
    {
       
    }

    /**
     * @see org.apache.turbine.Valve#invoke(RunData, ValveContext)
     */
    public void invoke(PipelineData pipelineData, ValveContext context)
        throws IOException, TurbineException
    {
        try
        {
            // This is where the validation of the Session information
            // is performed if the user has not logged in yet, then
            // the screen is set to be Login. This also handles the
            // case of not having a screen defined by also setting the
            // screen to Login. If you want people to go to another
            // screen other than Login, you need to change that within
            // TurbineResources.properties...screen.homepage; or, you
            // can specify your own SessionValidator action.
            ActionLoader.getInstance().exec(pipelineData, 
                    Turbine.getConfiguration().getString(ACTION_SESSION_VALIDATOR_KEY,
                            ACTION_SESSION_VALIDATOR_DEFAULT));
        }
        catch (Exception e)
        {
            throw new TurbineException(e);
        }            
    
        // Pass control to the next Valve in the Pipeline
        context.invokeNext(pipelineData);
    }
}