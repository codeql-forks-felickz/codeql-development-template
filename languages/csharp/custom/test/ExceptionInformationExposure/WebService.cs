using System;
using System.Web.Services;

namespace AsmxApp
{
    public struct Transaction
    {
        public bool Success;
        public string Message;
    }

    public class Services : WebService
    {
        [WebMethod]
        public Transaction TransferBalance(string debitAccount)
        {
            Transaction myTransact = new Transaction();
            myTransact.Success = false;
            myTransact.Message = "";
            try
            {
                Transfer(debitAccount);
                myTransact.Success = true;
            }
            catch (Exception e)
            {
                myTransact.Success = false;
                myTransact.Message = e.ToString(); // $ Source
            }
            return myTransact; // $ Alert
        }

        [WebMethod]
        public string Ping()
        {
            try
            {
                Transfer("1");
                return "ok";
            }
            catch (Exception e)
            {
                return e.Message; // $ Alert
            }
        }

        [WebMethod]
        public Transaction TransferBalanceSafe(string debitAccount)
        {
            Transaction myTransact = new Transaction();
            try
            {
                Transfer(debitAccount);
                myTransact.Success = true;
            }
            catch (Exception)
            {
                // GOOD: generic message.
                myTransact.Success = false;
                myTransact.Message = "Transaction failed.";
            }
            return myTransact;
        }

        // GOOD: not a web method, so the return value is not sent to a remote caller.
        public string Describe(Exception e)
        {
            return e.ToString();
        }

        private void Transfer(string account) { }
    }
}
