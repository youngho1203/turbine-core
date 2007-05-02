package org.apache.turbine.services.schedule;

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

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.turbine.services.TurbineServices;
import org.apache.turbine.services.pull.ApplicationTool;
import org.apache.turbine.util.TurbineException;

/**
 * This tool is used to retrieve information about the job scheduler.
 *
 * @author <a href="mailto:qmccombs@nequalsone.com">Quinton McCombs</a>
 * @version $Id$
 */
public class SchedulerTool implements ApplicationTool
{
    /** Used for logging */
    private static Log log = LogFactory.getLog(ScheduleService.LOGGER_NAME);

    /**
     * Initialize the pull tool
     */
    public void init(Object data)
    {
        if (!TurbineServices.getInstance().isRegistered(
                ScheduleService.SERVICE_NAME))
        {
            log.error("You can not use the SchedulerTool unless you enable "
                    +"the Scheduler Service!!!!");
        }
    }

    /**
     * Does nothing
     */
    public void refresh()
    {
    }

    /**
     * Gets the list of scheduled jobs.
     *
     * @return List of JobEntry objects.
     */
    public List getScheduledJobs()
    {
        return TurbineScheduler.listJobs();
    }

    /**
     * Determines if the scheduler service is currently enabled.
     */
    public boolean isEnabled()
    {
        return TurbineScheduler.isEnabled();
    }

    /**
     * Gets the job identified by the jobId.
     *
     * @param jobId Id of the job to retreive.
     * @return The job.  Null if the jobId is not found.
     */
    public JobEntry getJob(String jobId)
    {
        JobEntry je = null;

        try
        {
            je = TurbineScheduler.getJob(Integer.parseInt(jobId));
        }
        catch (TurbineException e)
        {
            log.error("Could not retreive job id #" + jobId, e);
        }

        return je;
    }

}
