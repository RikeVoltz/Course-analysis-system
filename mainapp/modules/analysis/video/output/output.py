import json
import os


def output(videos, course_name, path):
    """
    Write results of analysis to json file.
    :param videos:
    :param course_name:
    :param path:
    :return:
    """

    file_name = os.path.join(path, course_name + '_video_statistics.json')

    with open(file_name, "w") as out:
        sections = set()
        for video in videos:
            sections.add(video.section)

        course = dict()
        sections_j = []
        for section in sections:
            subsections = set()
            for video in videos:
                if video.section == section:
                    subsections.add(video.subsection)

            section_j = dict()
            subsections_j = []
            for subsection in subsections:
                subsection_j = dict()
                videos_j = []
                for video in videos:
                    # todo: can be empty
                    if (video.section == section) and (video.subsection == subsection):
                        video_j = dict()
                        video_j["user_percent"] = video.user_percent
                        video_j["page"] = video.page
                        video_j["watched_percent"] = video.watched_percent
                        video_j["intervals_number"] = video.intervals_number
                        video_j["review_intervals"] = video.review_intervals
                        video_j["length"] = video.length
                        videos_j.append(video_j)
                # todo: the sane with test
                subsection_j["subsection_name"] = subsection
                subsection_j["videos"] = videos_j
                subsections_j.append(subsection_j)
            section_j["section_name"] = section
            section_j["subsections"] = subsections_j
            sections_j.append(section_j)
        course["course_name"] = course_name
        course["sections"] = sections_j
        out.write(json.dumps(course))
    return file_name
