package org.apache.turbine.util;


import java.util.ArrayList;
import java.util.List;

/**
 * A message class for holding information about a message that
 * relates to a specific form and field.  Used together with
 * FormMessages class.
 *
 * @author <a href="mailto:neeme@one.lv">Neeme Praks</a>
 * @version $Id$
 */
public class FormMessage
{
    private String message;
    private String formName;
    private final List<String> fieldNames;

    /**
     * Constructor.
     */
    public FormMessage()
    {
        fieldNames = new ArrayList<String>();
    }

    /**
     * Constructor.
     *
     * @param formName A String with the form name.
     */
    public FormMessage(String formName)
    {
        this();
        setFormName(formName);
    }

    /**
     * Constructor.
     *
     * @param formName A String with the form name.
     * @param fieldName A String with the field name.
     */
    public FormMessage(String formName,
                       String fieldName)
    {
        this(formName);
        setFieldName(fieldName);
    }

    /**
     * Constructor.
     *
     * @param formName A String with the form name.
     * @param fieldName A String with the field name.
     * @param message A String with the message.
     */
    public FormMessage(String formName,
                       String fieldName,
                       String message)
    {
        this(formName, fieldName);
        setMessage(message);
    }

    /**
     * Return the message.
     *
     * @return A String with the message.
     */
    public String getMessage()
    {
        return message;
    }

    /**
     * Return the form name.
     *
     * @return A String with the form name.
     */
    public String getFormName()
    {
        return formName;
    }

    /**
     * Return the field names.
     *
     * @return A String[] with the field names.
     */
    public String[] getFieldNames()
    {
        return fieldNames.toArray(new String[fieldNames.size()]);
    }

    /**
     * Set the message.
     *
     * @param message A String with the message.
     */
    public void setMessage(String message)
    {
        this.message = message;
    }

    /**
     * Set the form name.
     *
     * @param formName A String with the form name.
     */
    public void setFormName(String formName)
    {
        this.formName = formName;
    }

    /**
     * Adds one field name.
     *
     * @param fieldName A String with the field name.
     */
    public void setFieldName(String fieldName)
    {
        fieldNames.add(fieldName);
    }

    /**
     * Write out the contents of the message in a friendly manner.
     *
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder("formName:" + getFormName() + ", fieldNames:");
        for (int i = 0; i< getFieldNames().length; i++){
            sb.append(getFieldNames()[i] + " ");
        }
        sb.append(", message:" + getMessage());

        return sb.toString();
    }
}
