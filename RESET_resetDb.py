import psycopg2
from config import CONFIG

DATABASE = CONFIG['DATABASE']

#End of user defined variables

dbconnection = psycopg2.connect("host={} dbname={} user={} password={}".format(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD']))
cursor = dbconnection.cursor()

#environment variables
cursor.execute("DELETE FROM environment_variables.mem_envars WHERE imagename > ''")
cursor.execute("DELETE FROM environment_variables.mem_envars_path WHERE imagename > ''")
cursor.execute("DELETE FROM environment_variables.triage_sysvariables_path WHERE imagename > ''")
cursor.execute("DELETE FROM environment_variables.triage_sysvariables WHERE imagename > ''")

#vt_hash_check
cursor.execute("DELETE FROM vt_hash_check.virustotal_results WHERE md5 > ''")

#ip_blacklist
cursor.execute("DELETE FROM ip_blacklist.blacklistedip WHERE ipaddress > ''")

# #log
# cursor.execute("DELETE FROM log.triage_applicationlog WHERE imagename > ''")
# cursor.execute("DELETE FROM log.triage_securitylog WHERE imagename > ''")
# cursor.execute("DELETE FROM log.triage_systemlog WHERE imagename > ''")

#process_list
cursor.execute("DELETE FROM process_list.mem_pslist WHERE imagename > ''")
cursor.execute("DELETE FROM process_list.mem_pstree WHERE imagename > ''")
cursor.execute("DELETE FROM process_list.mem_psxview WHERE imagename > ''")
cursor.execute("DELETE FROM process_list.triage_processes WHERE imagename > ''")
cursor.execute("DELETE FROM process_list.triage_processes_tree WHERE imagename > ''")
cursor.execute("DELETE FROM process_list.wmi_processes WHERE imagename > ''")
#project
cursor.execute("DELETE FROM project.project_image_mapping WHERE projectname > ''")

#system
cursor.execute("DELETE FROM system.triage_sysinfo WHERE imagename > ''")
cursor.execute("DELETE FROM system.triage_sysinfo_applications WHERE imagename > ''")
cursor.execute("DELETE FROM system.triage_sysinfo_hotfix WHERE imagename > ''")
cursor.execute("DELETE FROM system.triage_sysinfo_nic WHERE imagename > ''")
cursor.execute("DELETE FROM system.triage_sysinfo_nicip WHERE imagename > ''")
cursor.execute("DELETE FROM system.triage_sysinfo_partitions WHERE imagename > ''")
cursor.execute("DELETE FROM system.triage_sysinfo_processors WHERE imagename > ''")

#triage_network_connections
cursor.execute("DELETE FROM network.triage_network_connections WHERE imagename > ''")
cursor.execute("DELETE FROM network.mem_netscan WHERE imagename > ''")

#ipblacklist
cursor.execute("DELETE FROM ip_blacklist.blacklistedip WHERE ipaddress > ''")

#vulnerability
#cursor.execute("DELETE FROM vulnerability.windows_patch_level WHERE cveid > ''")
#cursor.execute("DELETE FROM vulnerability.cve_details WHERE cveID > ''")
#cursor.execute("DELETE FROM vulnerability.product WHERE cveID > ''")
#cursor.execute("DELETE FROM vulnerability.manufacturer WHERE product > ''")
dbconnection.commit()
