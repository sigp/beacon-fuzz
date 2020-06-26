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
import tech.pegasys.teku.datastructures.state.BeaconStateImpl;
import tech.pegasys.teku.datastructures.util.SimpleOffsetSerializer;
import tech.pegasys.teku.bls.BLSSignature;


@RunWith(JQF.class)
public class TekuFuzz {

  // Attestation
  @Fuzz /* JQF will generate inputs to this method */
  public void teku_attestation(InputStream input) {
  try {
    byte[] bytes = input.readAllBytes();
    Attestation structuredInput = 
    	SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), Attestation.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

  // AttesterSlashing
  @Fuzz
  public void teku_attester_slashing(InputStream input) {
  try {
    byte[] bytes = input.readAllBytes();
    AttesterSlashing structuredInput = 
    	SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), AttesterSlashing.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

  // BeaconBlock
  @Fuzz
  public void teku_block(InputStream input) {
  try {
    byte[] bytes = input.readAllBytes();
    BeaconBlock structuredInput = 
    	SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), BeaconBlock.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

  // TODO: SignedVoluntaryExit
  @Fuzz
  public void teku_signed_block(InputStream input) {
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
  try {
    byte[] bytes = input.readAllBytes();
    BeaconBlock structuredInput = 
    	SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), BeaconBlock.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

  // Deposit
  @Fuzz
  public void teku_deposit(InputStream input) {
  try {
    byte[] bytes = input.readAllBytes();
    Deposit structuredInput = 
      SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), Deposit.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

  // ProposerSlashing
  @Fuzz
  public void teku_proposer_slashing(InputStream input) {
  try {
    byte[] bytes = input.readAllBytes();
    ProposerSlashing structuredInput = 
      SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), ProposerSlashing.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }

// TODO: SignedVoluntaryExit
  @Fuzz
  public void teku_signed_voluntary_exit(InputStream input) {
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

// VoluntaryExit
  @Fuzz
  public void teku_voluntary_exit(InputStream input) {
  try {
    byte[] bytes = input.readAllBytes();
    VoluntaryExit structuredInput = 
      SimpleOffsetSerializer.deserialize(Bytes.wrap(bytes), VoluntaryExit.class);
  } catch (IOException e) {    
  } catch (InvalidSSZTypeException e){
  } catch (EndOfSSZException e){
  } catch (IllegalStateException e){
  } catch (IllegalArgumentException e){}
  }


  // BLSSignature
  @Fuzz
  public void teku_bls(InputStream input) {
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

