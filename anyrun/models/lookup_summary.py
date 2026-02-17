import os.path

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str
    ssdeep: str


class FileMetaData(BaseModel):
    filename: str
    filepath: str
    file_extension: Optional[str]
    hashes: FileHashes

class DestinationIpAsn(BaseModel):
    asn: str
    date: datetime


class Industry(BaseModel):
    industryName: str
    confidence: int


class RelatedFile(BaseModel):
    fileName: str
    fileExtension: str = Field(default=None)
    hashes: FileHashes


class RelatedDNS(BaseModel):
    domainName: str
    threatName: List[str]
    threatLevel: int
    date: datetime
    isMalconf: bool


class RelatedURL(BaseModel):
    url: str
    date: datetime
    threatLevel: int
    threatName: List[str]
    isMalconf: bool


class RelatedIP(BaseModel):
    destinationIP: str
    date: datetime
    threatLevel: int
    threatName: List[str]
    isMalconf: bool


class SourceTask(BaseModel):
    related: str


class Summary(BaseModel):
    threatLevel: Optional[int]
    lastSeen: Optional[datetime]
    tags: Optional[List[str]]


class LookupSummary(BaseModel):
    summary: Summary
    destination_port: List[int] = Field(alias="destinationPort")
    destination_ip_geo: List[str] = Field(alias="destinationIPgeo")
    destination_ip_asn: List[DestinationIpAsn] = Field(alias="destinationIpAsn")
    related_files: List[RelatedFile] = Field(alias="relatedFiles")
    related_industries: List[Industry] = Field(alias="industries")
    related_ips: List[RelatedIP] = Field(alias="destinationIP")
    related_dns: List[RelatedDNS] = Field(alias="relatedDNS")
    related_urls: List[RelatedURL] = Field(alias="relatedURLs")
    related_tasks: List[SourceTask] = Field(alias="sourceTasks")

    def is_empty(self) -> bool:
        """
        :return: True if object is not found in ANY.RUN TI Lookup else False.
        """
        for field, value in self.__dict__.items():
            if field == "summary":
                continue
            if value:
                return False

        return True

    def verdict(self) -> Optional[str]:
        """
        :return: Text verdict: No threats detected, Suspicious or Malicious.
        """
        verdict_mapping = {0: "No info", 1: "Suspicious", 2: "Malicious"}
        return verdict_mapping.get(self.summary.threatLevel, "No info") if self.summary.threatLevel is not None else None

    def last_modified(self) -> Optional[str]:
        """
        :return: Object last modified date.
        """
        return self.summary.lastSeen.strftime("%Y-%m-%d %H:%M:%S") if self.summary.lastSeen else None

    def tasks(self, tasks_range: int = 5) -> Optional[list[str]]:
        """
        :param tasks_range: The number of tasks to return.
        :return: The list of the last related tasks.
        """
        return [task.related for task in self.related_tasks[:tasks_range]] if self.related_tasks else None

    def tags(self) -> Optional[str]:
        """
        :return:  Object related tags.
        """
        return ", ".join(tag for tag in self.summary.tags) if self.summary.tags else None

    def industries(self) -> Optional[str]:
        """
        :return:  Object related industries with a confidence.
        """
        return ", ".join(
            [
                f'{industry.industryName}({industry.confidence}%)'
                for industry in sorted(
                    self.related_industries,
                    key=lambda x: x.confidence,
                    reverse=True
                )
            ]
        ) if self.related_industries else None

    def country(self) -> Optional[str]:
        """
        :return:  Object related country.
        """
        return self.destination_ip_geo[0] if self.destination_ip_geo else None

    def port(self) -> Optional[str]:
        """
        :return:  Object destination port.
        """
        return self.destination_port[0] if self.destination_port else None

    def asn(self) -> Optional[str]:
        """
        :return:  Object ASN owner.
        """
        return self.destination_ip_asn[0].asn if self.destination_ip_asn else None

    def file_meta(self) -> Optional[FileMetaData]:
        """
        :return:  Object related file meta data.
        """
        if not self.related_files:
            return None

        file_info = self.related_files[0]
        ext = file_info.fileExtension
        path = file_info.fileName
        name = os.path.basename(path) if "\\" not in path else path.split("\\")[-1]

        return FileMetaData(
            filename=name,
            filepath=path,
            file_extension=ext,
            hashes=file_info.hashes
        )

    @staticmethod
    def intelligence_url(object_value: str) -> str:
        """
        :return:  Link to the ANY.RUN TI Lookup request.
        """
        return "https://intelligence.any.run/analysis/lookup#{%22query%22:%22" + object_value + "%22,%22dateRange%22:180}"
