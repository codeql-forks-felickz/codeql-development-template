package com.example.shop

import android.app.Activity
import android.content.Context

class LoginActivity : Activity() {
    fun onLoginFailed() {
        for (info in packageManager.getInstalledPackages(0)) {
            val packageName = info.packageName
            if (packageName.startsWith("com.exampleplugin")) {
                val packageContext = createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY) // $ Alert
                packageContext.classLoader
                    .loadClass("com.exampleplugin.MainInterface")
                    .getMethod("getInstance", Context::class.java)
                    .invoke(null, this)
            }
        }
    }

    fun readResourcesOnly(packageName: String) {
        // Safe: does not load code while ignoring security.
        createPackageContext(packageName, Context.CONTEXT_RESTRICTED)
        createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE)
    }
}
