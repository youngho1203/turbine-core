package org.apache.turbine.services.freemarker;

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001 The Apache Software Foundation.  All rights
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

// FreeMarker Classes
import freemarker.template.SimpleScalar;
import freemarker.template.TemplateMethodModel;
import freemarker.template.TemplateModel;
import freemarker.template.TemplateModelException;

// Java stuff
import java.util.List;

// Turbine Utility Classes
import org.apache.turbine.util.DynamicURI;
import org.apache.turbine.util.RunData;

/**
 * Creates a TEXTAREA html tag.  The rows, columns, and wrap attribute
 * can be passed in through a list.  Extension of FreeMarker.
 *
 * @author <a href="mailto:john.mcnally@clearink.com">John D. McNally</a>
 * @version $Id$
 * @deprecated
 */
public class DynamicURIModel
    implements TemplateMethodModel
{
    private RunData data;

    /**
     * Constructor.
     *
     * @param data Turbine information.
     */
    public DynamicURIModel(RunData data)
    {
        this.data = data;
    }

    /**
     * Method called by FreeMarker during template parsing.  A list of
     * strings are passed in from the template.  The first string can
     * specify https or http or be the only required String which sets
     * the template parameter.  Any additional String pairs are taken
     * to be pathInfo data.  An "&" String can be used to specify
     * query data which should then be followed by pairs of Strings.
     * E.g (in a template where the DynamicURIModel has been stored
     * under the key "links":
     * ${links("http", "/subdir/directions.html",
     *         "from", "LA", "&", "to", "SF")}
     *
     * @param args A List of Strings passed from the template.
     * @return A TemplateModel with a String representation of the
     * DynamicURI.
     * @exception TemplateModelException.
     */
    public TemplateModel exec(List args)
        throws TemplateModelException
    {
        DynamicURI uri = new DynamicURI(data);
        String firstArg = (String)args.get(0);
        int start=1;
        if (firstArg.startsWith("http"))
        {
            int colonPosition = firstArg.indexOf(':');
            if (colonPosition == -1)
            {
                uri.setServerScheme(firstArg);
            }
            else
            {
                uri.setServerScheme(firstArg.substring(0,colonPosition));
                int secondColonPosition = firstArg.indexOf(':', colonPosition+1);
                if (secondColonPosition == -1)
                {
                    uri.setServerName( firstArg.substring(colonPosition+3) );
                }
                else
                {
                    uri.setServerName(firstArg.substring(colonPosition+3, secondColonPosition));
                    uri.setServerPort(Integer.parseInt(firstArg.substring(secondColonPosition+1)));
                }
            }
            uri.addPathInfo("template", (String)args.get(1));
            start=2;
        }
        else
        {
            uri.addPathInfo("template", firstArg.replace('/', ','));
        }
        boolean firstOfPair = true;
        boolean queryData = false;
        String first = null;
        for (int i=start; i<args.size(); i++)
        {
            String tempArg = (String)args.get(i);
            if (firstOfPair)
            {
                if (tempArg.equals("?"))
                {
                    queryData = true;
                }
                else
                {
                    first = tempArg;
                    firstOfPair = false;
                }
            }
            else
            {
                if (queryData)
                {
                    uri.addQueryData(first, tempArg);
                }
                else
                {
                    uri.addPathInfo(first, tempArg);
                }
                firstOfPair = true;
            }
        }
        return new SimpleScalar( uri.toString() );
    }

    /**
     * Required method in TemplateMethodModel, not implemented.
     *
     * @return Always false.
     */
    public boolean isEmpty()
    {
        return false;
    }
}