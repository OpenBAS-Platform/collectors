package io.openex.collectors.mitre_attack.batch.attack_pattern;


import org.json.JSONArray;
import org.springframework.batch.item.ItemReader;
import org.springframework.batch.item.NonTransientResourceException;
import org.springframework.batch.item.ParseException;
import org.springframework.batch.item.UnexpectedInputException;

import java.util.ArrayList;
import java.util.List;

public class CustomItemReaderAttackPattern implements ItemReader<org.json.JSONObject> {

  List<org.json.JSONObject> items = new ArrayList<>();

  public CustomItemReaderAttackPattern(JSONArray objects) {
    for (int i = 0; i < objects.length(); i++) {
      org.json.JSONObject object = objects.getJSONObject(i);
      if (object.getString("type").equals("attack-pattern")) {
        this.items.add(object);
      }
    }
  }

  public org.json.JSONObject read() throws UnexpectedInputException, NonTransientResourceException, ParseException {

    if (!items.isEmpty()) {
      return items.removeFirst();
    }
    return null;
  }
}
