import android.app.Activity
import android.content.IntentFilter

class ProductListActivity : Activity() {
    private val productDetailBroadCast = ProductDetailReceiver()

    fun onCreate() {
        val intentFilter = IntentFilter("com.example.action.PRODUCT_DETAIL")
        registerReceiver(productDetailBroadCast, intentFilter) // $ Alert
    }

    fun onCreateSafe() {
        val intentFilter = IntentFilter("com.example.action.PRODUCT_DETAIL")
        registerReceiver(productDetailBroadCast, intentFilter, RECEIVER_NOT_EXPORTED)
    }
}
