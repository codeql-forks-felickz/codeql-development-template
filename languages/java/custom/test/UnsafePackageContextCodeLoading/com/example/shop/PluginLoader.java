package com.example.shop;

import android.content.Context;

public class PluginLoader {
    private static final int UNSAFE_FLAGS = Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY;

    public Object loadUnsafe(Context context, String packageName) throws Exception {
        Context pluginContext = context.createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY); // $ Alert
        return pluginContext.getClassLoader().loadClass("com.exampleplugin.Plugin").newInstance();
    }

    public Object loadUnsafeViaConstant(Context context, String packageName) throws Exception {
        Context pluginContext = context.createPackageContext(packageName, UNSAFE_FLAGS); // $ Alert
        return pluginContext.getClassLoader().loadClass("com.exampleplugin.Plugin").newInstance();
    }

    public Object loadUnsafeViaLocal(Context context, String packageName) throws Exception {
        int flags = Context.CONTEXT_IGNORE_SECURITY | Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_RESTRICTED;
        Context pluginContext = context.createPackageContext(packageName, flags); // $ Alert
        return pluginContext.getClassLoader().loadClass("com.exampleplugin.Plugin").newInstance();
    }

    public Object loadSigned(Context context, String packageName) throws Exception {
        // Safe: code is loaded without ignoring security.
        Context pluginContext = context.createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE);
        return pluginContext.getClassLoader().loadClass("com.exampleplugin.Plugin").newInstance();
    }

    public Context resourcesOnly(Context context, String packageName) throws Exception {
        // Safe: code is not included.
        return context.createPackageContext(packageName, Context.CONTEXT_IGNORE_SECURITY);
    }
}
