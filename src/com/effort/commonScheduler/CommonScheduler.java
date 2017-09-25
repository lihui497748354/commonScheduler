package com.effort.commonScheduler;

import org.apache.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Created by Administrator on 2017/9/25.
 */
public class CommonScheduler {

    private static final Logger logger = Logger.getLogger(CommonScheduler.class);

    private Timer timer;

    private ExecutorService executorService;

    /**
     *
     */
    public void startService(){

        executorService = Executors.newFixedThreadPool(10);
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                timerVlues();
            }
        };
        timer = new Timer();
        timer.scheduleAtFixedRate(task,0,5*1000);
        montiStopCommonScheduler();
    }
    private void montiStopCommonScheduler(){
        ServerSocket serverSocket = null;
        try {
            InetAddress inetAddress = InetAddress.getByName("127.0.0.1");
            serverSocket = new ServerSocket(10057,10,inetAddress);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        while(true){
            try {
                logger.info("listening to the command port");
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                String request = inputStream.readUTF();
                if(null != request && request.equals("STOP")){
                    timer.cancel();
                    timer.purge();
                    executorService.shutdown();
                    while(!executorService.isTerminated()){}
                    logger.info("Common 管理的服务器已经关闭了..");
                    break;
                }
                inputStream.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    private void timerVlues(){
        logger.info("定时器执行任务。。。。。。");
    }

    /**
     *
     */
    public void stopService(){
        sendStopCommand(10057,"STOP");
    }
    private void sendStopCommand(int Port,String stopString){
        try {
            Socket socket = new Socket("127.0.0.1",Port);
            socket.setSoTimeout(60*1000);
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF(stopString);
            logger.info("发送停止命令,停止服务运行中...");
            dataOutputStream.close();
            socket.close();
        } catch (IOException e) {
            logger.error("stopService -- "+e);
        }
    }
}
