package logActivityAnalysis.activityTrackers;

import logData.log;
import logData.logReader;

/**
 * Skeleton of the tracker class every type of attack will use#
 */
public class tracker {
    protected String src; // source IP
    protected float threatLevel; // how threatening is the attack as a number
    protected String threatRisk;// how threatening is the attack as a string
    protected Integer count = 0; // how many attempts

    public String getSrc() {return src;}

    public Integer getCount() {
        return count;
    }

    /**
     * TODO rework the threat system
     */
    public void setThreat(){
        threatLevel = (float) this.getCount()/logReader.logsRead;
        if (threatLevel > 0.2){
            this.threatRisk = "High";
        }
        else if (threatLevel > 0.1){
            this.threatRisk = "Medium";
        }
        else{
            this.threatRisk = "Low";
        }
    }
}
