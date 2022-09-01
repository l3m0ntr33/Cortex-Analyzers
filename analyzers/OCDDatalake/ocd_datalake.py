#!/usr/bin/env python3
# encoding: utf-8

import traceback
from cortexutils.analyzer import Analyzer
from datalake import Datalake, AtomType, Output


class OCDDatalakeAnalyzer(Analyzer):
    DTL_MAPPING = {
        "url": AtomType.URL,
        "domain": AtomType.DOMAIN,
        "fqdn": AtomType.FQDN,
        "hash": AtomType.FILE,
        "ip": AtomType.IP
    }

    def __init__(self):
        Analyzer.__init__(self)
        self.username = self.get_param("config.username", None, "Missing username")
        self.password = self.get_param("config.password", None, "Missing password")
        self.env = self.get_param("config.env", "prod")
        try:
            self.dtl = Datalake(username=self.username, password=self.password, env=self.env)
        except Exception as e:
            self.error(str(e))

    def run(self):
        if self.data_type not in self.DTL_MAPPING.keys():
            self.error("Invalid data type")
        try:
            results = self.dtl.Threats.lookup(atom_value=self.get_data(),
                                              atom_type=self.DTL_MAPPING[self.data_type],
                                              hashkey_only=False,
                                              output=Output.JSON)
        except Exception as e:
            self.error(str(e))
        self.report({"results": results})

    def summary(self, raw):
        try:
            taxonomies = []
            max_score = 0
            threat_type = None

            for score_object in raw.get('results', {}).get('scores'):
                score = score_object['score']['risk']
                if score >= max_score:
                    max_score = score
                    threat_type = score_object['threat_type']

            if max_score == 0:
                level = "safe"
            if 0 < max_score < 30:
                level = "info"
            if 30 <= max_score < 50:
                level = "suspicious"
            if max_score >= 50:
                level = "malicious"

            taxonomies.append(self.build_taxonomy(level,
                                                  "OCD",
                                                  self.service,
                                                  "[{}]{}".format(threat_type, str(max_score))))
            return {"taxonomies": taxonomies}

        except Exception as e:
            self.error(traceback.format_exc())

if __name__ == "__main__":
    OCDDatalakeAnalyzer().run()
