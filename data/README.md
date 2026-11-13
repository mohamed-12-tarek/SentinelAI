
Raw network data was collected over a period of 5 days, Monday through Friday, and stored in PCAP files. 
Monday was used to create most of the Benign data, while the Attack-Network implemented various types of attacks over the next 4 days, 
such as Brute Force connections (FTP and SSH), several types of DoS attacks, as well as a Botnet attack, Infiltration attacks and subsequent Port-Scanning activity.

The PCAP data was processed using a tool developed by one of the authors of [1], called CICFlowMeter [3]. 
This tool produces flow traces:  sequences of packets between specific source and destination IP, with corresponding values for source and destination ports. 
TCP flows are usually terminated by connection teardowns, while UDP flows are terminated by a flow timeout. 
For each of these flow traces many features were selected, measuring flow characteristics, such as packet size, number of packets, flow duration, etc. 
For some of these variables, statistics such as their mean and standard deviations are provided as features as well. 
While several features are categorical (such as IP addresses, Port numbers and TCP flag counts), most of the other features are numerical. 

The result is the CICIDS-2017 dataset, with about 80 features and several attack families which can ultimately be divided in 16 categories: 
one Benign category and 15 Attack categories. This original dataset is available at [4]. Subsequently, the authors of [2] spent a lot of effort 
to correct some errors in the dataset, by fixing the CICFlowMeter software (especially regarding TCP flow terminations) and by 
re-labeling some of the samples accordingly. They posted the corrected dataset on their website [5]; 
this also has links to their GitHub site, which provides Python code that can be used to efficiently import the data. 
I used that as a starting point for my notebook, here on Kaggle.

For each of the 5 days a csv file with network flows was produced. 

These are the files in the dataset, with some changes: I created decimal values for the IP-addresses, and I removed a couple of rows with inf values.


[1] Sharafaldin I., Lashkari A.H., and Ghorbani A.A. Toward generating a new intrusion detection dataset and intrusion traffic characterization, Proceedings of the 4th International Conference on Information Systems Security and Privacy ICISSP - Volume 1, 108-116, 2018.
[2] Engelen G., Rimmer V., and Joosen W. Troubleshooting an intrusion detection dataset: the CICIDS2017 case study, 2021 IEEE Security and Privacy Workshops (SPW), 2021:7-12.
[3] https://www.unb.ca/cic/research/applications.html
[4] https://www.unb.ca/cic/datasets/ids-2017.html
[5] https://intrusion-detection.distrinet-research.be/CNS2022/index.html


