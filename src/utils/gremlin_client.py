# graphdb_tool.py
# Minimal, agent-ready Gremlin tool for Cosmos DB (Gremlin API).
# Actions:
#   1) analyze_vulnerability_impact (by cve_id)
#   2) blast_radius (by hosts/apps)
#   3) responsible_teams (for host/app or lists)

from typing import List, Dict, Any, Optional
from gremlin_python.driver import client, serializer
from dotenv import load_dotenv
load_dotenv()


class GremlinClient:
    def __init__(
        self,
        endpoint: str,
        database: str,
        graph: str,
        primary_key: str,
    ):
        self.g = client.Client(
            url=endpoint,
            traversal_source="g",
            username=f"/dbs/{database}/colls/{graph}",
            password=primary_key,
            message_serializer=serializer.GraphSONSerializersV2d0()
        )

    # ------------------------
    # low-level helpers
    # ------------------------
    def _q(self, query: str, **bindings) -> List[Any]:
        return self.g.submit(query, bindings=bindings).all().result()

    def _ids(self, it: List[Any]) -> List[str]:
        # Cosmos returns GraphSON; ids may already be strings
        return [str(x) for x in it]

    # ------------------------
    # 0) seed helpers
    # ------------------------
    def hosts_for_cve(self, cve_id: str) -> List[str]:
        q = """
        g.V().has('Vulnerability','cve_id',cve).
          in('VULNERABLE_TO').out('INSTALLED_ON').dedup().id()
        """
        return self._ids(self._q(q, cve=cve_id))

    def apps_for_hosts(self, host_ids: List[str]) -> List[str]:
        q = """
        g.V().hasId(within(hids)).
          out('HOSTS').dedup().id()
        """
        return self._ids(self._q(q, hids=list(host_ids)))

    # ------------------------
    # 1) analyzing vulnerability impact
    # ------------------------
    def analyze_vulnerability_impact(self, cve_id: str, hops: int = 3) -> Dict[str, Any]:
        # repeat().emit().until(loops()==hops) — Cosmos-friendly
        q = f"""
        g.V().has('Vulnerability','cve_id',cve).as('v').
          in('VULNERABLE_TO').dedup().aggregate('pkgs').
          out('INSTALLED_ON').dedup().aggregate('hosts').
          out('HOSTS').dedup().aggregate('apps').
          out('DEPLOYS').dedup().aggregate('svcs').
          repeat(out('DEPENDS_ON')).emit().until(loops().is({hops})).dedup().aggregate('down').
          select('pkgs','hosts','apps','svcs','down').
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold())
        """
        res = self._q(q, cve=cve_id)
        if not res:
            return {"cve_id": cve_id, "packages": [], "hosts": [], "applications": [], "services": [], "downstream_services": [], "counts": {}}
        r = res[0]
        out = {
            "cve_id": cve_id,
            "packages": r["pkgs"],
            "hosts": r["hosts"],
            "applications": r["apps"],
            "services": r["svcs"],
            "downstream_services": r["down"],
        }
        out["counts"] = {k: len(out[k]) for k in ["packages","hosts","applications","services","downstream_services"]}
        return out

    # ------------------------
    # 2) identifying blast radius
    # ------------------------
    def blast_radius_by_hosts(self, host_ids: List[str], hops: int = 3) -> Dict[str, Any]:
        q = f"""
        g.V().hasId(within(hids)).dedup().aggregate('hosts').
          select('hosts').unfold().out('HOSTS').dedup().aggregate('apps').
          select('apps').unfold().out('DEPLOYS').dedup().aggregate('svcs').
          select('svcs').unfold().
            repeat(out('DEPENDS_ON')).emit().until(loops().is({hops})).dedup().aggregate('down').
          select('hosts').unfold().out('PART_OF').dedup().aggregate('systems').
          select('hosts','apps','svcs','down','systems').
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold())
        """
        res = self._q(q, hids=list(host_ids))
        if not res:
            return {"hosts": [], "applications": [], "services": [], "downstream_services": [], "systems": [], "counts": {}}
        r = res[0]
        out = {
            "hosts": r["hosts"],
            "applications": r["apps"],
            "services": r["svcs"],
            "downstream_services": r["down"],
            "systems": r["systems"],
        }
        out["counts"] = {k: len(out[k]) for k in ["hosts","applications","services","downstream_services","systems"]}
        return out

    def blast_radius_by_apps(self, app_ids: List[str], hops: int = 3) -> Dict[str, Any]:
        q = f"""
        g.V().hasId(within(aids)).dedup().aggregate('apps').
          select('apps').unfold().out('DEPLOYS').dedup().aggregate('svcs').
          select('svcs').unfold().
            repeat(out('DEPENDS_ON')).emit().until(loops().is({hops})).dedup().aggregate('down').
          select('apps','svcs','down').
            by(unfold().id().fold()).
            by(unfold().id().fold()).
            by(unfold().id().fold())
        """
        res = self._q(q, aids=list(app_ids))
        if not res:
            return {"applications": [], "services": [], "downstream_services": [], "counts": {}}
        r = res[0]
        out = {
            "applications": r["apps"],
            "services": r["svcs"],
            "downstream_services": r["down"],
        }
        out["counts"] = {k: len(out[k]) for k in ["applications","services","downstream_services"]}
        return out

    # ------------------------
    # 3) responsible teams
    # ------------------------
    def team_for_host(self, host_id: str) -> List[str]:
        q = "g.V().hasId(hid).in('MONITORS').dedup().id()"
        return self._ids(self._q(q, hid=host_id))

    def team_for_app(self, app_id: str) -> List[str]:
        q = "g.V().hasId(aid).in('OWNS').dedup().id()"
        return self._ids(self._q(q, aid=app_id))

    def teams_for_hosts(self, host_ids: List[str]) -> List[str]:
        q = "g.V().hasId(within(hids)).in('MONITORS').dedup().id()"
        return self._ids(self._q(q, hids=list(host_ids)))

    def teams_for_apps(self, app_ids: List[str]) -> List[str]:
        q = "g.V().hasId(within(aids)).in('OWNS').dedup().id()"
        return self._ids(self._q(q, aids=list(app_ids)))

    # ------------------------
    # optional: end-to-end from CVE to blast radius
    # ------------------------
    def blast_radius_by_cve(self, cve_id: str, hops: int = 3) -> Dict[str, Any]:
        return self.analyze_vulnerability_impact(cve_id, hops=hops)

    # ------------------------
    # comprehensive CVE analysis with blast radius and team mapping
    # ------------------------
    def comprehensive_cve_analysis(self, cve_id: str, hops: int = 3) -> Dict[str, Any]:
        """
        Performs comprehensive vulnerability analysis for a given CVE ID.
        
        Args:
            cve_id (str): The CVE identifier to analyze
            hops (int): Number of hops for blast radius analysis (default: 3)
            
        Returns:
            Dict[str, Any]: Comprehensive analysis including:
                - vulnerability impact analysis
                - individual blast radius for each affected host and app
                - team responsibility mapping for each host and app
        """
        result = {
            "cve_id": cve_id,
            "analysis_timestamp": None,  # Can be populated with datetime if needed
            "vulnerability_impact": {},
            "host_blast_radius": {},
            "app_blast_radius": {},
            "host_team_mapping": {},
            "app_team_mapping": {},
            "summary": {
                "total_affected_hosts": 0,
                "total_affected_apps": 0,
                "total_responsible_teams": 0,
                "unique_teams": set()
            }
        }
        
        try:
            # Step 1: Run vulnerability impact analysis
            print(f"Analyzing vulnerability impact for {cve_id}...")
            impact_analysis = self.analyze_vulnerability_impact(cve_id, hops)
            result["vulnerability_impact"] = impact_analysis
            
            affected_hosts = impact_analysis.get("hosts", [])
            affected_apps = impact_analysis.get("applications", [])
            
            result["summary"]["total_affected_hosts"] = len(affected_hosts)
            result["summary"]["total_affected_apps"] = len(affected_apps)
            
            # Step 2: Calculate blast radius for each host individually
            print(f"Calculating blast radius for {len(affected_hosts)} hosts...")
            for host_id in affected_hosts:
                try:
                    host_blast_radius = self.blast_radius_by_hosts([host_id], hops)
                    result["host_blast_radius"][host_id] = host_blast_radius
                except Exception as e:
                    print(f"Error calculating blast radius for host {host_id}: {e}")
                    result["host_blast_radius"][host_id] = {"error": str(e)}
            
            # Step 3: Calculate blast radius for each app individually
            print(f"Calculating blast radius for {len(affected_apps)} applications...")
            for app_id in affected_apps:
                try:
                    app_blast_radius = self.blast_radius_by_apps([app_id], hops)
                    result["app_blast_radius"][app_id] = app_blast_radius
                except Exception as e:
                    print(f"Error calculating blast radius for app {app_id}: {e}")
                    result["app_blast_radius"][app_id] = {"error": str(e)}
            
            # Step 4: Identify teams responsible for each host
            print(f"Identifying teams for {len(affected_hosts)} hosts...")
            for host_id in affected_hosts:
                try:
                    teams = self.team_for_host(host_id)
                    result["host_team_mapping"][host_id] = teams
                    result["summary"]["unique_teams"].update(teams)
                except Exception as e:
                    print(f"Error identifying teams for host {host_id}: {e}")
                    result["host_team_mapping"][host_id] = {"error": str(e)}
            
            # Step 5: Identify teams responsible for each app
            print(f"Identifying teams for {len(affected_apps)} applications...")
            for app_id in affected_apps:
                try:
                    teams = self.team_for_app(app_id)
                    result["app_team_mapping"][app_id] = teams
                    result["summary"]["unique_teams"].update(teams)
                except Exception as e:
                    print(f"Error identifying teams for app {app_id}: {e}")
                    result["app_team_mapping"][app_id] = {"error": str(e)}
            
            # Finalize summary
            result["summary"]["total_responsible_teams"] = len(result["summary"]["unique_teams"])
            result["summary"]["unique_teams"] = list(result["summary"]["unique_teams"])
            
            print(f"Analysis complete for {cve_id}")
            print(f"Summary: {result['summary']['total_affected_hosts']} hosts, "
                  f"{result['summary']['total_affected_apps']} apps, "
                  f"{result['summary']['total_responsible_teams']} unique teams")
            
        except Exception as e:
            print(f"Error in comprehensive analysis for {cve_id}: {e}")
            result["error"] = str(e)
        
        return result


# Example usage (remove/replace in agent runtime)
if __name__ == "__main__":
    import os
    GREMLIN_DB = os.getenv("GREMLIN_DB")
    GREMLIN_GRAPH_NAME = os.getenv("GREMLIN_GRAPH_NAME")
    GREMLIN_PRIMARY_KEY = os.getenv("GREMLIN_PRIMARY_KEY")
    GREMLIN_ENDPOINT = os.getenv("GREMLIN_ENDPOINT")
    GREMLIN_PARTITION_KEY = os.getenv("GREMLIN_PARTITION_KEY")

    graph_db = GremlinClient(GREMLIN_ENDPOINT, GREMLIN_DB, GREMLIN_GRAPH_NAME, GREMLIN_PRIMARY_KEY)
    
    # Example of individual function calls
    print("analyze_vulnerability_impact",graph_db.analyze_vulnerability_impact("CVE-2022-3602", hops=3))
    print("blast_radius_by_apps",graph_db.blast_radius_by_apps(["app_1","app_5"], hops=2))
    print("blast_radius_by_hosts",graph_db.blast_radius_by_hosts(["host_001","host_003"], hops=2))
    print("blast_radius_by_cve",graph_db.blast_radius_by_cve("CVE-2022-3602", hops=3))
    print("team_for_host",graph_db.team_for_host("host_001"))
    print("team_for_app",graph_db.team_for_app("app_1"))
    print("teams_for_hosts",graph_db.teams_for_hosts(["host_001","host_003"]))
    print("teams_for_apps",graph_db.teams_for_apps(["app_1","app_5"]))
    
    # Example of comprehensive analysis
    print("\n=== Comprehensive CVE Analysis ===")
    comprehensive_result = graph_db.comprehensive_cve_analysis("CVE-2022-3602", hops=3)
    print(comprehensive_result)