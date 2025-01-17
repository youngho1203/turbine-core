package org.apache.turbine.test;

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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hsqldb.jdbcDriver;

public class HsqlDB
{
    private Connection connection = null;
    private static Log log = LogFactory.getLog(HsqlDB.class);

    public HsqlDB(String uri, String loadFile)
            throws Exception
    {
        Class.forName(jdbcDriver.class.getName());

        this.connection = DriverManager.getConnection(uri, "sa", "");

        if (StringUtils.isNotEmpty(loadFile))
        {
            loadSqlFile(loadFile);
        }
    }

    public Connection getConnection()
    {
        return connection;
    }

    public void close()
    {
        try
        {
            connection.close();
        }
        catch (Exception e)
        {
            // ignore
        }
    }

    private void loadSqlFile(String fileName)
            throws Exception
    {
        try (Statement statement = connection.createStatement())
        {
            String commands = getFileContents(fileName);

            for (int targetPos = commands.indexOf(';'); targetPos > -1; targetPos = commands.indexOf(';'))
            {
                String cmd = commands.substring(0, targetPos + 1).trim();

                if (cmd.startsWith("--"))
                {
                    // comment
                    int lineend = commands.indexOf('\n');
                    if (lineend > -1)
                    {
                        targetPos = lineend - 1;
                    }
                }
                else
                {
                    try
                    {
                        statement.execute(cmd);
                    }
                    catch (SQLException sqle)
                    {
                        log.warn("Statement: " + cmd + ": " + sqle.getMessage());
                    }
                }

                commands = commands.substring(targetPos + 2);
            }
        }
    }

    private String getFileContents(String fileName)
            throws Exception
    {
        byte[] bytes = Files.readAllBytes(Paths.get(fileName));

        return new String(bytes, StandardCharsets.ISO_8859_1);
    }
}

