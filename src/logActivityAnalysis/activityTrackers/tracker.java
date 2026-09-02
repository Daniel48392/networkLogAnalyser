package logActivityAnalysis.activityTrackers;

import logData.logReader;

public class tracker {
    protected String src;
    protected float threatLevel;
    protected String threatRisk;
    protected Integer count = 0;

    public Integer getCount() {
        return count;
    }

    public void setThreat(){
        threatLevel = (float) this.getCount()/logReader.logsRead;
        if (threatLevel > 0.2){
            this.threatRisk = "High"; // rework Number TODO
        }
        else if (threatLevel > 0.1){
            this.threatRisk = "Medium";
        }
        else{
            this.threatRisk = "Low";
        }
    }
}
