package io.projectdiscovery.nuclei.util;

import io.projectdiscovery.nuclei.model.Requests;
import io.projectdiscovery.nuclei.model.Status;
import io.projectdiscovery.nuclei.model.Template;
import io.projectdiscovery.nuclei.model.Word;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.util.Objects;

public class YamlUtil {

    public static String dumpYaml(Template template) {
        final Representer representer = new Representer() {
            @Override
            protected NodeTuple representJavaBeanProperty(Object javaBean, Property property, Object propertyValue, Tag customTag) {
                if (Objects.isNull(propertyValue)) {
                    return null; // skip fields with null value
                }
                return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag);
            }
        };

        final TypeDescription typeDescription = new TypeDescription(Requests.class, Tag.MAP);
        // TODO isn't there a more elegant way to remap field names?
        typeDescription.substituteProperty("matchers-condition", Requests.class, "getMatchersCondition", "setMatchersCondition");
        typeDescription.setExcludes("matchersCondition");

        representer.addTypeDescription(typeDescription);
        representer.addClassTag(Word.class, Tag.MAP);
        representer.addClassTag(Status.class, Tag.MAP);

        final DumperOptions options = new DumperOptions();
        options.setIndent(2);
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        final Yaml yaml = new Yaml(representer, options);
        return yaml.dumpAsMap(template);
    }
}
