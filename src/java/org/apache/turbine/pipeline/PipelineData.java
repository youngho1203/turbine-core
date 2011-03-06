package org.apache.turbine.pipeline;

import java.util.Map;


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


/**
 * <p>A <b>PipelineData</b> is a holder for data being passed from one
 * Valve to the next.
 * The detailed contract for a Valve is included in the description of
 * the <code>invoke()</code> method below.</p>
 *
 * <b>HISTORICAL NOTE</b>:  The "PipelineData" name was assigned to this
 * holder as it functions similarily to the RunData object, but without
 * the additional methods
 *
 * @author <a href="mailto:epugh@opensourceconnections.com">Eric Pugh</a>
 * @author <a href="mailto:peter@courcoux.biz">Peter Courcoux</a>
 */
public interface PipelineData
{
    public void put(Class<?> name, Map<?, ?> value);

    public Map<?, ?> get(Class<?> name);

    public Object get(Class<?> key, Object innerKey);
}
