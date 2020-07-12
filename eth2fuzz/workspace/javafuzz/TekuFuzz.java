/*
 * Copyright 2020 Patrick Ventuzelo
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import java.io.InputStream;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.ssz.InvalidSSZTypeException;
import org.apache.tuweni.ssz.EndOfSSZException;
import org.junit.runner.RunWith;
import java.io.IOException;
import tech.pegasys.teku.datastructures.operations.Attestation;
import tech.pegasys.teku.datastructures.operations.AttesterSlashing;
import tech.pegasys.teku.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.datastructures.blocks.SignedBeaconBlock;
import tech.pegasys.teku.datastructures.operations.Deposit;
import tech.pegasys.teku.datastructures.operations.ProposerSlashing;
import tech.pegasys.teku.datastructures.operations.SignedVoluntaryExit;
import tech.pegasys.teku.datastructures.operations.VoluntaryExit;
import tech.pegasys.teku.datastructures.state.BeaconState;
import tech.pegasys.teku.datastructures.state.MutableBeaconState;
import tech.pegasys.teku.datastructures.state.BeaconStateImpl;
import tech.pegasys.teku.datastructures.util.SimpleOffsetSerializer;
import tech.pegasys.teku.bls.BLSSignature;
import java.util.Random;
import java.util.Collections;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import tech.pegasys.teku.util.config.Constants;
import tech.pegasys.teku.datastructures.util.BeaconStateUtil;
import tech.pegasys.teku.ssz.SSZTypes.SSZList;
import tech.pegasys.teku.core.BlockProcessorUtil;
import tech.pegasys.teku.core.StateTransition;
import tech.pegasys.teku.core.StateTransitionException;
import tech.pegasys.teku.core.exceptions.BlockProcessingException;
import com.google.common.primitives.UnsignedLong;
import java.io.FileInputStream;

/* useful links:
- https://github.com/PegaSysEng/teku/blob/master/ethereum/datastructures/src/main/java/tech/pegasys/teku/datastructures/util/SimpleOffsetSerializer.java
*/

@RunWith(JQF.class)
public class TekuFuzz {

  // global beaconstate (null if uninitialized)
  public static BeaconState GlobalBeaconState;

  public static void main(String[] args) {

    // compilation
    // javac -cp .:$(./tekuclass.sh) TekuFuzz.java

    // use DEBUG_BEACONSTATE and DEBUG_CONTAINER env

    // Run the debug cli
    // DEBUG_BEACONSTATE=beaconstate.ssz DEBUG_CONTAINER=ssz.ssz CLASSPATH=$CLASSPATH:$(./tekuclass.sh) java TekuFuzz


    TekuFuzz tk = new TekuFuzz();

    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();

    try {
      // get the beaconstate
      String env_beaconstate = System.getenv("DEBUG_BEACONSTATE");
      File f = new File(env_beaconstate);
      byte[] fileContent = Files.readAllBytes(f.toPath());
      tk.GlobalBeaconState = SimpleOffsetSerializer.deserialize(Bytes.wrap(fileContent), BeaconStateImpl.class);
      System.out.println("[+] beaconstate ok");
    }catch (IOException e) {
      System.out.println("[X] loading beaconstate failed");
    }

    // get the ssz container
    String env_ssz = System.getenv("DEBUG_CONTAINER");
    File f2 = new File(env_ssz);
    try (InputStream in = new FileInputStream(f2)) {
      // call your target here
      tk.teku_attester_slashing(in);
      System.out.println("[+] ssz container ok");
    }
    catch (IOException e) {
      System.out.println("[X] loading ssz container failed");
    }
  System.out.println("[+] No crash");
  }

  public void get_beaconstate() {

    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();

    // get environment variable
    String env_beaconstate = System.getenv("ETH2FUZZ_BEACONSTATE");
    //System.out.println("ETH2FUZZ_BEACONSTATE: " + env_beaconstate);

    // Load file names inside beaconstate folder
    File f = new File(env_beaconstate);
    ArrayList<String> pathnames = new ArrayList<String>(Arrays.asList(f.list()));
    
    // shuffle list of beaconstate
    Collections.shuffle(pathnames);

    // pick one file randomly
    Random rand = new Random();

    // For each pathname in the pathnames array
    for (String pathname : pathnames) {

      // try to pick and load one beaconstate randomly
      try {
        String item = pathnames.get(rand.nextInt(pathnames.size()));
        //System.out.println(env_beaconstate + "/" + item);

        Path p1 = Paths.get(env_beaconstate + "/" + item); 
        byte[] fileContent = Files.readAllBytes(p1);
        //System.out.println(item);
        TekuFuzz.GlobalBeaconState = SimpleOffsetSerializer.deserialize(Bytes.wrap(fileContent), BeaconStateImpl.class);
        return;

      } catch (IOException e) {
        System.out.println("IOException exception");
      } catch (InvalidSSZTypeException e){
      } catch (EndOfSSZException e){
      }
    }

    //System.out.println(TekuFuzz.GlobalBeaconState.getSlot());
    //System.out.println("OK");
}




  // Attestation
  @Fuzz /* JQF will generate inputs to this method */
  public void teku_attestation(InputStream input) {

    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }

      byte[] bytes = input.readAllBytes();
      // create attestation
      Attestation structuredInput = 
        SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), Attestation.class);
    
      // processing container
      TekuFuzz.GlobalBeaconState.updated(
        state -> {
          BlockProcessorUtil.process_attestations(
              state, SSZList.singleton(structuredInput));
        });

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    } catch (BlockProcessingException e){
    }
  }

  // AttesterSlashing
  @Fuzz
  public void teku_attester_slashing(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }

      byte[] bytes = input.readAllBytes();
      AttesterSlashing structuredInput = 
       SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), AttesterSlashing.class);

    
      // processing container
      TekuFuzz.GlobalBeaconState.updated(
        state -> {
          BlockProcessorUtil.process_attester_slashings(
              state, SSZList.singleton(structuredInput));
        });

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    } catch (BlockProcessingException e){
    }
  }

  // BeaconBlock
  @Fuzz
  public void teku_block(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
  try {

    if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }


    byte[] bytes = input.readAllBytes();
    SignedBeaconBlock structuredInput = 
      SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), SignedBeaconBlock.class);

    // prevent timeout when dealing with huge slot value
    if(structuredInput.getSlot().compareTo(
        TekuFuzz.GlobalBeaconState.getSlot().plus(UnsignedLong.valueOf("100"))) > 0
      ){
      StateTransition transition = new StateTransition();
      BeaconState postState =
            transition.initiate(
                TekuFuzz.GlobalBeaconState,
                structuredInput,
                false);
    }



  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (StateTransitionException e){
  } catch (IllegalArgumentException e){}
  }

  // TODO: SignedVoluntaryExit
  @Fuzz
  public void teku_signed_block(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
  try {
    byte[] bytes = input.readAllBytes();
    SignedVoluntaryExit structuredInput = 
      SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), SignedVoluntaryExit.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

  // TODO: BeaconBlock
  @Fuzz
  public void teku_block_header(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }

      byte[] bytes = input.readAllBytes();
      BeaconBlock structuredInput = 
       SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), BeaconBlock.class);

    
      // processing container
      TekuFuzz.GlobalBeaconState.updated(
        state -> {
          BlockProcessorUtil.process_block_header(
              state, structuredInput);
        });

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    } catch (BlockProcessingException e){
    }
  }

  // Deposit
  @Fuzz
  public void teku_deposit(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }

      byte[] bytes = input.readAllBytes();
      Deposit structuredInput = 
       SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), Deposit.class);

    
      // processing container
      TekuFuzz.GlobalBeaconState.updated(
        state -> {
          BlockProcessorUtil.process_deposits(
              state, SSZList.singleton(structuredInput));
        });

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    } catch (BlockProcessingException e){
    }
  }

  // ProposerSlashing
  @Fuzz
  public void teku_proposer_slashing(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }

      byte[] bytes = input.readAllBytes();
      ProposerSlashing structuredInput = 
       SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), ProposerSlashing.class);

    
      // processing container
      TekuFuzz.GlobalBeaconState.updated(
        state -> {
          BlockProcessorUtil.process_proposer_slashings(
              state, SSZList.singleton(structuredInput));
        });

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    } catch (BlockProcessingException e){
    }
  }

// TODO: SignedVoluntaryExit
  @Fuzz
  public void teku_signed_voluntary_exit(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      if (TekuFuzz.GlobalBeaconState == null) {
        get_beaconstate();
      }

      byte[] bytes = input.readAllBytes();
      SignedVoluntaryExit structuredInput = 
       SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), SignedVoluntaryExit.class);

    
      // processing container
      TekuFuzz.GlobalBeaconState.updated(
        state -> {
          BlockProcessorUtil.process_voluntary_exits(
              state, SSZList.singleton(structuredInput));
        });

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    } catch (BlockProcessingException e){
    }
  }

  // VoluntaryExit
  @Fuzz
  public void teku_voluntary_exit(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
    try {

      byte[] bytes = input.readAllBytes();
      VoluntaryExit structuredInput = 
       SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), VoluntaryExit.class);

  

    } catch (IOException e) {    
    } catch (InvalidSSZTypeException e){
    } catch (EndOfSSZException e){
    } catch (IllegalStateException e){
    } catch (IllegalArgumentException e){
    }
  }

  // BLSSignature
  @Fuzz
  public void teku_bls(InputStream input) {
    // mainnet config
    Constants.setConstants("mainnet");
    SimpleOffsetSerializer.setConstants();
  try {
    byte[] bytes = input.readAllBytes();
    BLSSignature structuredInput = 
      SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), BLSSignature.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

}



// enr
// https://github.com/PegaSysEng/teku/blob/b5f23a4d2b704713699fdee6e1839b6c2d9dddb6/networking/p2p/src/test/java/tech/pegasys/teku/networking/p2p/discovery/discv5/NodeRecordConverterTest.java#L44
