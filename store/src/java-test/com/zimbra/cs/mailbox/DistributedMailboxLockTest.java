package com.zimbra.cs.mailbox;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.MockProvisioning;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.mailbox.Mailbox.FolderNode;
import com.zimbra.cs.service.util.ItemId;

public class DistributedMailboxLockTest {
	   @BeforeClass
	    public static void init() throws Exception {
	        MailboxTestUtil.initServer();
	        Provisioning prov = Provisioning.getInstance();
	        prov.createAccount("test@zimbra.com", "secret", new HashMap<String, Object>());
	    }

	    @Before
	    public void setup() throws Exception {
	        MailboxTestUtil.clearData();
	        MailboxManager.getInstance().getMailboxByAccountId(MockProvisioning.DEFAULT_ACCOUNT_ID);
	    }

	    @Test
	    public void multiAccess() throws ServiceException {
	        final Mailbox mbox = MailboxManager.getInstance().getMailboxByAccountId(MockProvisioning.DEFAULT_ACCOUNT_ID);

	        //just do some read/write in different threads to see if we trigger any deadlocks or other badness
	        int numThreads = 2;
	        final int loopCount = 1;
	        final long sleepTime = 10;
	        int joinTimeout = 10000;

	        List<Thread> threads = new ArrayList<Thread>(numThreads * 2);
	        for (int i = 0; i < numThreads; i++) {
	            String threadName = "MailboxLockTest-MultiReader-" + i;
	            Thread reader = new Thread(threadName) {
	                @Override
	                public void run() {
	                    for (int i = 0; i < loopCount; i++) {
	                        //mbox.lock.lock(false);
					ZimbraLog.mailbox.info("starting reader");
	                        try {
	                            ItemId iid = new ItemId(mbox, Mailbox.ID_FOLDER_USER_ROOT);
	                            FolderNode node = mbox.getFolderTree(null, iid, true);
	                        } catch (ServiceException e) {
	                            e.printStackTrace();
	                            Assert.fail("ServiceException");
	                        }
	                        try {
	                            Thread.sleep(sleepTime);
	                        } catch (InterruptedException e) {
	                        }
	                        ZimbraLog.mailbox.info("ending reader");
	                        //mbox.lock.release();
	                    }
	                }
	            };
	            threads.add(reader);

	            threadName = "MailboxLockTest-MultiWriter-" + i;
	            Thread writer = new Thread(threadName) {
	                @Override
	                public void run() {
	                    for (int i = 0; i < loopCount; i++) {
	                        //mbox.lock.lock(true);
	                        mbox.dLock.lock();
	                        ZimbraLog.mailbox.info("writer gets lock");
	                        try {
	                            mbox.createFolder(null, "foo-" + Thread.currentThread().getName() + "-" + i, new Folder.FolderOptions().setDefaultView(MailItem.Type.MESSAGE));
	                        } catch (ServiceException e) {
	                            e.printStackTrace();
	                            Assert.fail("ServiceException");
	                        }
	                        //mbox.lock.release();
	                        try {
	                            Thread.sleep(20000);
	                            //Thread.sleep(sleepTime);
	                        } catch (InterruptedException e) {
	                        }
	                        mbox.dLock.release();
	                        ZimbraLog.mailbox.info("writer release lock");
	                    }
	                }
	            };
	            threads.add(writer);
//	            writer.start();
//	            reader.start();
	        }

	        for (Thread t : threads){
	            t.start();
	        }
	        for (Thread t : threads) {
	            try {
	                t.join();
	                //t.join(joinTimeout);
	                Assert.assertFalse(t.isAlive());
	            } catch (InterruptedException e) {
	            }
	        }
	    }
}
